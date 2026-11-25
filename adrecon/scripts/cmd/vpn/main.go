// cmd/vpn — VPN connector. Реализует fortinet (openconnect) и sonicwall
// (netExtender) под флагом --vendor.
//
// Использование:
//   vpn --vendor=fortinet       (по умолчанию)
//   vpn --vendor=sonicwall
//
// Пишет: routes.txt, dns.txt, split_dns_domains.txt (если получены).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"runner/internal/cfg"
	"runner/internal/logx"
	"runner/internal/netx"
	"runner/internal/procx"
)

type vpnConfig struct {
	IP, Port, Login, Password, Vendor, Group string
}

var vendorProto = map[string]string{
	"fortinet": "fortinet", "fortigate": "fortinet",
	"cisco": "anyconnect", "anyconnect": "anyconnect",
	"pulse": "pulse", "ivanti": "pulse",
	"globalprotect": "gp", "paloalto": "gp",
	"f5": "f5", "juniper": "nc",
}

// ─── Парсеры вывода openconnect ───────────────────────────────────────────

var (
	reDNS     = regexp.MustCompile(`Got IPv4 DNS server (\d+\.\d+\.\d+\.\d+)`)
	reSplitNS = regexp.MustCompile(`Got Split DNS domain ([^\s]+)`)
	reRoute   = regexp.MustCompile(`Got IPv4 route (\d+\.\d+\.\d+\.\d+)/(\d+\.\d+\.\d+\.\d+)`)
	reRouteC  = regexp.MustCompile(`split.*route (\d+\.\d+\.\d+\.\d+/\d+)`)
	reCert    = regexp.MustCompile(`pin-sha256:([A-Za-z0-9+/=]{20,60})`)
)

func maskCIDR(network, mask string) string {
	ip := net.ParseIP(mask)
	if ip == nil {
		return ""
	}
	m4 := ip.To4()
	if m4 == nil {
		return ""
	}
	ones := 0
	for _, b := range m4 {
		for i := 0; i < 8; i++ {
			if (b<<uint(i))&0x80 != 0 {
				ones++
			} else {
				return fmt.Sprintf("%s/%d", network, ones)
			}
		}
	}
	return fmt.Sprintf("%s/%d", network, ones)
}

func parseDNS(o string) (private, public []string) {
	seen := map[string]bool{}
	for _, m := range reDNS.FindAllStringSubmatch(o, -1) {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			if netx.IsPrivateIP(m[1]) {
				private = append(private, m[1])
			} else {
				public = append(public, m[1])
			}
		}
	}
	return
}

func parseSplitDNS(o string) []string {
	seen := map[string]bool{}
	var d []string
	for _, m := range reSplitNS.FindAllStringSubmatch(o, -1) {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			d = append(d, m[1])
		}
	}
	return d
}

func parseRoutes(o string) []string {
	seen := map[string]bool{}
	var r []string
	for _, m := range reRoute.FindAllStringSubmatch(o, -1) {
		if len(m) > 2 {
			c := maskCIDR(m[1], m[2])
			if c != "" && !seen[c] {
				seen[c] = true
				r = append(r, c)
			}
		}
	}
	for _, m := range reRouteC.FindAllStringSubmatch(o, -1) {
		if len(m) > 1 && !seen[m[1]] {
			seen[m[1]] = true
			r = append(r, m[1])
		}
	}
	return r
}

func extractCert(o string) string {
	for _, m := range reCert.FindAllStringSubmatch(o, -1) {
		if len(m) > 1 {
			h := m[1]
			if strings.HasPrefix(h, "AAAA") || strings.Contains(h, "DUMMY") {
				continue
			}
			return h
		}
	}
	return ""
}

// ─── Загрузка конфигов ────────────────────────────────────────────────────

func loadVPNConfigs() []vpnConfig {
	var cfgs []vpnConfig
	if d, err := os.ReadFile("job_config.json"); err == nil {
		var jc cfg.FullJobConfig
		if json.Unmarshal(d, &jc) == nil {
			for _, cr := range jc.Credentials {
				if cr.Login == "" {
					continue
				}
				port := "443"
				if jc.Port > 0 {
					port = fmt.Sprintf("%d", jc.Port)
				}
				cfgs = append(cfgs, vpnConfig{
					IP: jc.IP, Port: port, Login: cr.Login, Password: cr.Password,
					Vendor: jc.Vendor, Group: jc.Group,
				})
			}
		}
	}
	if len(cfgs) == 0 {
		if f, err := os.Open("input.txt"); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				l := strings.TrimSpace(sc.Text())
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				p := strings.SplitN(l, ":", 4)
				if len(p) >= 4 && p[2] != "" {
					cfgs = append(cfgs, vpnConfig{
						IP: p[0], Port: p[1], Login: p[2], Password: p[3],
						Vendor: "fortinet", Group: "default",
					})
				}
			}
		}
	}
	return cfgs
}

func isRoot() bool { return os.Geteuid() == 0 }

func killVPN() {
	exec.Command("pkill", "-9", "-f", "openconnect").Run()
	exec.Command("pkill", "-9", "-f", "openvpn").Run()
	exec.Command("pkill", "-9", "-f", "netExtender").Run()
	time.Sleep(time.Second)
}

func waitTun(maxSec int) bool {
	_, ok := netx.WaitTun(time.Duration(maxSec) * time.Second)
	return ok
}

func getCertHash(c vpnConfig) string {
	proto := vendorProto[c.Vendor]
	if proto == "" {
		proto = "fortinet"
	}
	url := "https://" + c.IP + ":" + c.Port
	dummy := "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	proxyArg := ""
	if p := os.Getenv("EXIT_PROXY"); p != "" {
		proxyArg = " --proxy=" + p
		logx.Info("[CERT] probing %s via %s", url, p)
	} else {
		logx.Info("[CERT] probing %s", url)
	}
	shCmd := fmt.Sprintf("echo '%s' | openconnect --protocol=%s --user=%s --passwd-on-stdin --servercert %s%s %s",
		strings.ReplaceAll(c.Password, "'", `'"'"'`), proto, c.Login, dummy, proxyArg, url)
	var buf bytes.Buffer
	cmd := exec.Command("bash", "-c", shCmd)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Run()
	out := buf.String()
	h := extractCert(out)
	if h != "" {
		logx.OK("[CERT] hash: pin-sha256:%s", h)
	} else {
		logx.Warn("[CERT] could not extract hash")
	}
	return h
}

// connectFortinet — openconnect с персистентным reconnect и парсингом DNS/routes на лету.
func connectFortinet(c vpnConfig, certHash string) *exec.Cmd {
	proto := vendorProto[c.Vendor]
	if proto == "" {
		proto = "fortinet"
	}
	url := "https://" + c.IP + ":" + c.Port
	cert := "pin-sha256:" + certHash

	args := []string{
		"--protocol=" + proto,
		"--user=" + c.Login,
		"--passwd-on-stdin",
		"--servercert", cert,
		"--reconnect-timeout", "60",
		"--force-dpd", "30",
		"--disable-ipv6",
		"--no-dtls",
	}
	if p := os.Getenv("EXIT_PROXY"); p != "" {
		args = append(args, "--proxy="+p)
		logx.Info("[VPN] exit proxy: %s", p)
	}
	args = append(args, url)

	cmd := exec.Command("openconnect", args...)
	procx.SetPgid(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		logx.Err("[VPN] stdin pipe: %v", err)
		return nil
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		logx.Err("[VPN] start: %v", err)
		return nil
	}
	logx.Info("[VPN] PID %d", cmd.Process.Pid)

	go func() {
		stdin.Write([]byte(c.Password + "\n"))
	}()

	var mu sync.Mutex
	var out bytes.Buffer
	var dnsDone, routesDone bool

	stream := func(r io.Reader, label string) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			fmt.Printf("  [VPN|%s] %s\n", label, line)

			mu.Lock()
			out.WriteString(line + "\n")
			snap := out.String()
			mu.Unlock()

			if strings.Contains(line, "Got IPv4 DNS") && !dnsDone {
				priv, pub := parseDNS(snap)
				if len(priv) > 0 {
					cfg.WriteLines("dns.txt", priv)
					logx.OK("[DNS] private DNS → dns.txt: %v", priv)
					dnsDone = true
				}
				if len(pub) > 0 {
					logx.Info("[DNS] skipping public DNS: %v", pub)
				}
			}
			if (strings.Contains(line, "Got IPv4 route") || strings.Contains(line, "split")) && !routesDone {
				rs := parseRoutes(snap)
				if len(rs) > 0 {
					cfg.WriteLines("routes.txt", rs)
					logx.OK("[ROUTES] %d → routes.txt: %v", len(rs), rs)
					routesDone = true
				}
			}
			if strings.Contains(line, "Split DNS") {
				if d := parseSplitDNS(snap); len(d) > 0 {
					cfg.WriteLines("split_dns_domains.txt", d)
				}
			}
		}
	}
	go stream(stdout, "out")
	go stream(stderr, "err")
	return cmd
}

func runFortinet(c vpnConfig) int {
	logx.Info("Vendor: fortinet | Target: %s@%s:%s", c.Login, c.IP, c.Port)
	if !isRoot() {
		logx.Warn("not root — TUN may fail")
	}
	killVPN()

	cert := getCertHash(c)
	if cert == "" {
		logx.Err("Could not get server cert")
		return 1
	}

	var vpnCmd *exec.Cmd
	connected := false
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			logx.Warn("Retry %d/3", attempt)
			killVPN()
			time.Sleep(time.Duration(attempt*3) * time.Second)
		}
		vpnCmd = connectFortinet(c, cert)
		if vpnCmd == nil {
			continue
		}
		if waitTun(30) {
			connected = true
			logx.OK("VPN connected on attempt %d", attempt)
			time.Sleep(3 * time.Second)
			break
		}
		logx.Warn("No tun, killing")
		if vpnCmd.Process != nil {
			procx.KillGroup(vpnCmd.Process.Pid)
		}
		vpnCmd = nil
	}
	if !connected {
		logx.Err("VPN not established after 3 attempts")
		return 1
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Watchdog: перезапуск при падении tun
	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		restarts := 0
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if netx.ActiveTunIface() == "" {
					restarts++
					if restarts > 5 {
						logx.Err("Watchdog: too many restarts, giving up")
						return
					}
					logx.Warn("Watchdog: tun down, reconnect %d/5", restarts)
					killVPN()
					time.Sleep(3 * time.Second)
					if cmd := connectFortinet(c, cert); cmd != nil && waitTun(30) {
						logx.OK("Watchdog: VPN restored")
						go cmd.Wait()
						restarts = 0
					}
				} else {
					restarts = 0
				}
			}
		}
	}()

	done := make(chan error, 1)
	go func() { done <- vpnCmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			logx.Warn("VPN process exited: %v — watchdog handles", err)
			<-sig
		}
	case <-sig:
		close(stop)
		killVPN()
	}
	return 0
}

// ─── SonicWall (netExtender) ──────────────────────────────────────────────

func findNetExtender() string {
	for _, p := range []string{"netExtender", "/usr/sbin/netExtender", "/usr/local/sbin/netExtender", "/opt/netExtender/netExtender"} {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func runSonicwall(c vpnConfig) int {
	logx.Info("Vendor: sonicwall | Target: %s@%s:%s", c.Login, c.IP, c.Port)
	bin := findNetExtender()
	if bin == "" {
		logx.Err("netExtender not found")
		return 1
	}
	killVPN()

	domain := "LocalDomain"
	server := fmt.Sprintf("%s:%s", c.IP, c.Port)
	cmd := exec.Command(bin,
		"-u", c.Login, "-p", c.Password, "-d", domain, server)
	procx.SetPgid(cmd)
	stdin, _ := cmd.StdinPipe()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		logx.Err("netExtender start: %v", err)
		return 1
	}
	logx.Info("netExtender PID %d", cmd.Process.Pid)

	go func() {
		defer stdin.Close()
		time.Sleep(2 * time.Second)
		for i := 0; i < 10; i++ {
			stdin.Write([]byte("Y\n"))
			time.Sleep(time.Second)
		}
	}()

	if !waitTun(60) {
		logx.Err("netExtender: no tun after 60s")
		procx.KillGroup(cmd.Process.Pid)
		return 1
	}
	logx.OK("SonicWall VPN established")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		<-sig
	case <-sig:
		procx.TermGroup(cmd.Process.Pid)
		time.Sleep(time.Second)
		procx.KillGroup(cmd.Process.Pid)
	}
	return 0
}

// ─── main ─────────────────────────────────────────────────────────────────

func main() {
	vendor := flag.String("vendor", "", "vpn vendor: fortinet|sonicwall|<empty>=from config")
	flag.Parse()

	fmt.Println("═══ VPN Connector v10.0 ═══")
	cfgs := loadVPNConfigs()
	if len(cfgs) == 0 {
		logx.Err("no credentials in job_config.json / input.txt")
		os.Exit(1)
	}
	c := cfgs[0]
	if *vendor != "" {
		c.Vendor = *vendor
	}
	if c.Vendor == "" {
		c.Vendor = "fortinet"
	}

	// Чистим старые артефакты
	os.Remove("dns.txt")
	os.Remove("routes.txt")
	os.Remove("split_dns_domains.txt")

	switch strings.ToLower(c.Vendor) {
	case "sonicwall", "sonic", "netextender":
		os.Exit(runSonicwall(c))
	default:
		os.Exit(runFortinet(c))
	}
}
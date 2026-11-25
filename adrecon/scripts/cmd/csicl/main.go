// cmd/csicl — внутриконтейнерный пайплайн-оркестратор.
// Фиксы: убран go run, добавлен context + kill process group через procx,
// общий cfg + logx + netx, единый pre-seed.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"runner/internal/cfg"
	"runner/internal/logx"
	"runner/internal/netx"
	"runner/internal/procx"
)

const (
	VPNWaitTimeout  = 30 * time.Second
	ProbeTimeout    = 5 * time.Second
	RouteSettleWait = 10 * time.Second
	BinDir          = "/app/bin"
)

type stepResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration"`
	Error    string `json:"error,omitempty"`
}

var stepResults []stepResult

func addStep(name, status, dur, errMsg string) {
	stepResults = append(stepResults, stepResult{name, status, dur, errMsg})
}

func writeStepsMeta() {
	d, _ := json.MarshalIndent(stepResults, "", "  ")
	os.WriteFile("pipeline_steps.json", d, 0644)
}

// runStep запускает бинарь с таймаутом; при истечении — kill всей группы.
func runStep(ctx context.Context, stepName, bin string, timeout time.Duration, args ...string) error {
	logx.Info("running %s", stepName)
	st := time.Now()

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, bin, args...)
	procx.SetPgid(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		logx.Err("%s: start: %v", stepName, err)
		addStep(stepName, "failed", time.Since(st).Round(time.Millisecond).String(), err.Error())
		return err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		dur := time.Since(st).Round(time.Millisecond).String()
		if err != nil {
			logx.Err("%s done in %s: %v", stepName, dur, err)
			addStep(stepName, "failed", dur, err.Error())
			return err
		}
		logx.OK("%s done in %s", stepName, dur)
		addStep(stepName, "ok", dur, "")
		return nil
	case <-cctx.Done():
		procx.KillGroup(cmd.Process.Pid)
		<-done
		err := cctx.Err()
		logx.Err("%s timeout: %v", stepName, err)
		addStep(stepName, "failed", time.Since(st).Round(time.Millisecond).String(), err.Error())
		return err
	}
}

// runBG — фоновый запуск VPN (с Setpgid), возвращает cmd.
func runBG(name, bin string, args ...string) *exec.Cmd {
	logx.Info("starting %s in background", name)
	cmd := exec.Command(bin, args...)
	procx.SetPgid(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		logx.Err("%s start: %v", name, err)
		return nil
	}
	logx.OK("%s PID %d", name, cmd.Process.Pid)
	return cmd
}

// ─── Pre-seed input_data ──────────────────────────────────────────────────

func preSeed(input cfg.InputData) {
	if len(input.Targets) > 0 {
		cfg.WriteLines("routes.txt", input.Targets)
		logx.OK("routes.txt: %d targets", len(input.Targets))
	}
	var dnsEntries []string
	dnsEntries = append(dnsEntries, input.DCIPs...)
	dnsEntries = append(dnsEntries, input.DNSServers...)
	if len(dnsEntries) > 0 {
		cfg.WriteLines("dns.txt", dnsEntries)
		logx.OK("dns.txt: %d entries", len(dnsEntries))
	}
	if input.Domain != "" {
		cfg.WriteLines("domain.txt", []string{input.Domain})
		cfg.WriteLines("ldap_domains.txt", []string{input.Domain})
		cfg.WriteLines("smb_domains.txt", []string{input.Domain})
		logx.OK("domain: %s", input.Domain)
	}
	if len(input.KnownUsers) > 0 {
		cfg.WriteLines("domain_users.txt", input.KnownUsers)
	}
	if len(input.KnownCreds) > 0 {
		var smbL, ldapL []string
		for _, c := range input.KnownCreds {
			d := c.Domain
			if d == "" {
				d = input.Domain
			}
			smbL = append(smbL, fmt.Sprintf("smb|manual|445|manual|%s|%s|%s", d, c.Login, c.Password))
			ldapL = append(ldapL, fmt.Sprintf("ldap|manual|389|manual|%s|%s|%s", d, c.Login, c.Password))
		}
		cfg.WriteLines("smb_valid.txt", smbL)
		cfg.WriteLines("ldap_valid.txt", ldapL)
	}
	if len(input.SMBTargets) > 0 {
		cfg.WriteLines("smb_custom_targets.txt", input.SMBTargets)
	}
	if len(input.LDAPTargets) > 0 {
		cfg.WriteLines("ldap_custom_targets.txt", input.LDAPTargets)
	}
	if len(input.ExcludeIPs) > 0 {
		cfg.WriteLines("exclude_ips.txt", input.ExcludeIPs)
	}
}

// ─── Pipeline gates ───────────────────────────────────────────────────────

func shouldRun(step string, p cfg.PipelineConfig) bool {
	for _, s := range p.SkipSteps {
		if strings.EqualFold(s, step) {
			return false
		}
	}
	if len(p.Steps) > 0 {
		for _, s := range p.Steps {
			if strings.EqualFold(s, step) {
				return true
			}
		}
		return false
	}
	return true
}

func shouldStop(step string, p cfg.PipelineConfig) bool {
	for _, s := range p.StopOnFail {
		if strings.EqualFold(s, step) {
			return true
		}
	}
	return false
}

// ─── Exit IP check ────────────────────────────────────────────────────────

func checkExitIP(proxy string) {
	urls := []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"}
	for _, u := range urls {
		args := []string{"-sf", "--max-time", "15"}
		if proxy != "" {
			args = append(args, "--proxy", proxy)
		}
		args = append(args, u)
		out, err := exec.Command("curl", args...).Output()
		ip := strings.TrimSpace(string(out))
		if err == nil && ip != "" {
			logx.OK("exit IP: %s", ip)
			if proxy != "" {
				logx.OK("via proxy: %s", proxy)
			}
			return
		}
	}
	if proxy != "" {
		logx.Err("proxy %s not working", proxy)
		out, err := exec.Command("curl", "-sf", "--max-time", "10", "https://api.ipify.org").Output()
		if err == nil {
			logx.Warn("direct IP (NO proxy): %s", strings.TrimSpace(string(out)))
		}
	} else {
		logx.Warn("could not determine exit IP")
	}
}

// ─── Connectivity probe ───────────────────────────────────────────────────

func probeConnectivity(dcs []string, vpnIP string) []string {
	var reachable []string
	for _, dc := range dcs {
		host := strings.Split(dc, ":")[0]
		if host == vpnIP {
			continue
		}
		l389 := netx.PortOpen(host, 389, ProbeTimeout)
		l636 := netx.PortOpen(host, 636, ProbeTimeout)
		s445 := netx.PortOpen(host, 445, ProbeTimeout)
		msg := fmt.Sprintf("[PROBE] %s ldap:%v ldaps:%v smb:%v", host, l389, l636, s445)
		if l389 || l636 || s445 {
			logx.OK("%s", msg)
			reachable = append(reachable, host)
		} else {
			logx.Warn("%s", msg)
		}
	}
	return reachable
}

// ─── main ─────────────────────────────────────────────────────────────────

func main() {
	logx.Head("\n╔══════════════════════════════════╗")
	logx.Head("║  Container Runner v10.0          ║")
	logx.Head("╚══════════════════════════════════╝")

	cwd, _ := os.Getwd()
	logx.Info("CWD: %s", cwd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		logx.Warn("signal received — killing VPN")
		cancel()
		exec.Command("pkill", "-9", "-f", "openconnect").Run()
		exec.Command("pkill", "-9", "-f", "openvpn").Run()
		exec.Command("pkill", "-9", "-f", "netExtender").Run()
		writeStepsMeta()
		os.Exit(0)
	}()

	c := cfg.Load()
	logx.Info("vendor=%s group=%s mode=%s modules=%v timeout=%ds creds=%d",
		c.Vendor, c.Group, c.Scan.Mode, c.Scan.Modules, c.Scan.Timeout, len(c.Credentials))

	step := 0
	nextStep := func(label string) {
		step++
		logx.Step(step, label)
	}

	pipelineStart := time.Now()

	// ── Pre-seed input data ──
	if c.InputData.Targets != nil || c.InputData.DCIPs != nil ||
		c.InputData.Domain != "" || c.InputData.KnownCreds != nil {
		nextStep("Pre-seed Input Data")
		st := time.Now()
		preSeed(c.InputData)
		addStep("input_data", "ok", time.Since(st).Round(time.Millisecond).String(), "")
	}

	// ── Proxy / Network check ──
	if shouldRun("proxy_check", c.Pipeline) {
		nextStep("Network Check")
		checkExitIP(os.Getenv("EXIT_PROXY"))
	}

	// ── VPN ──
	var vpnCmd *exec.Cmd
	if shouldRun("vpn", c.Pipeline) && !c.InputData.SkipVPN {
		nextStep("VPN Connection")
		st := time.Now()
		vendor := c.Vendor
		if vendor == "" {
			vendor = "fortinet"
		}
		vpnCmd = runBG("VPN ("+vendor+")", filepath.Join(BinDir, "vpn"), "--vendor="+vendor)

		defer func() {
			logx.Info("cleanup: killing VPN")
			if vpnCmd != nil && vpnCmd.Process != nil {
				procx.TermGroup(vpnCmd.Process.Pid)
				time.Sleep(time.Second)
			}
			exec.Command("pkill", "-9", "-f", "openconnect").Run()
			exec.Command("pkill", "-9", "-f", "openvpn").Run()
			exec.Command("pkill", "-9", "-f", "netExtender").Run()
		}()

		if vpnCmd == nil {
			addStep("vpn", "failed", time.Since(st).Round(time.Millisecond).String(), "start failed")
			if shouldStop("vpn", c.Pipeline) {
				writeStepsMeta()
				_ = runStep(ctx, "report", filepath.Join(BinDir, "reporter"), 2*time.Minute)
				os.Exit(1)
			}
		} else {
			if tun, ok := netx.WaitTun(VPNWaitTimeout); ok {
				logx.OK("VPN tunnel: %s", tun)
				addStep("vpn", "ok", time.Since(st).Round(time.Millisecond).String(), "")
			} else {
				logx.Err("No tun/ppp after %v", VPNWaitTimeout)
				addStep("vpn", "failed", time.Since(st).Round(time.Millisecond).String(), "no tun")
				if shouldStop("vpn", c.Pipeline) {
					writeStepsMeta()
					_ = runStep(ctx, "report", filepath.Join(BinDir, "reporter"), 2*time.Minute)
					os.Exit(1)
				}
			}
		}
	} else if c.InputData.SkipVPN {
		logx.Info("VPN skipped (skip_vpn=true)")
		addStep("vpn", "skipped", "0ms", "skip_vpn")
	}

	// ── Routes ──
	if shouldRun("routes", c.Pipeline) {
		nextStep("Route Collection")
		_ = runStep(ctx, "routes", filepath.Join(BinDir, "routes"), 1*time.Minute)
		rs := cfg.ReadLines("routes.txt")
		ds := cfg.ReadLines("dns.txt")
		logx.Info("routes (%d): %s", len(rs), strings.Join(rs, ", "))
		logx.Info("dns (%d): %s", len(ds), strings.Join(ds, ", "))
	}

	// ── Nmap ──
	if shouldRun("nmap", c.Pipeline) {
		nextStep("Nmap Scan")
		_ = runStep(ctx, "nmap", filepath.Join(BinDir, "nmap"), time.Duration(c.Scan.Timeout)*time.Minute)
	}

	// ── Probe ──
	if shouldRun("probe", c.Pipeline) {
		nextStep("Connectivity Check")
		dcList := cfg.ReadLines("dns.txt")
		reach := probeConnectivity(dcList, c.IP)
		if len(reach) == 0 && len(dcList) > 0 {
			logx.Warn("no DC reachable — waiting %v", RouteSettleWait)
			time.Sleep(RouteSettleWait)
			reach = probeConnectivity(dcList, c.IP)
		}
		if len(reach) > 0 {
			logx.OK("reachable DCs: %s", strings.Join(reach, ", "))
		}
	}

	// ── NXC ──
	if shouldRun("nxc", c.Pipeline) {
		nextStep(fmt.Sprintf("NXC Scanner [mode=%s, modules=%d]", c.Scan.Mode, len(c.Scan.Modules)))
		_ = runStep(ctx, "nxc", filepath.Join(BinDir, "nxc"), time.Duration(c.Scan.Timeout)*time.Minute)
	}

	// ── LDAP deep enum ──
	if shouldRun("ldap_enum", c.Pipeline) {
		if hasCreds("ldap_valid.txt", "smb_valid.txt") {
			nextStep("LDAP Deep Enumeration")
			_ = runStep(ctx, "ldap_enum", filepath.Join(BinDir, "ldapenum"), 30*time.Minute)
		} else {
			logx.Info("no valid creds — skipping ldap_enum")
			addStep("ldap_enum", "skipped", "0ms", "no creds")
		}
	}

	// ── Kerbrute ──
	if shouldRun("kerbrute", c.Pipeline) {
		if c.Kerbrute.Enabled {
			nextStep("Kerbrute")
			_ = runStep(ctx, "kerbrute", filepath.Join(BinDir, "kerbrute"), 60*time.Minute)
		} else {
			addStep("kerbrute", "skipped", "0ms", "not enabled")
		}
	}

	// ── Report ──
	if shouldRun("report", c.Pipeline) {
		nextStep("Report Generator")
		writeStepsMeta()
		os.WriteFile("pipeline_duration.txt",
			[]byte(time.Since(pipelineStart).Round(time.Millisecond).String()), 0644)
		_ = runStep(ctx, "report", filepath.Join(BinDir, "reporter"), 2*time.Minute)
	}

	// ── Summary ──
	fmt.Println()
	logx.Info("output files:")
	for _, pat := range []string{
		"network_report_*.json", "scan_result.json",
		"ldap_enum_report_*.json", "nmap_results.json",
		"kerbrute_results.json", "sqlmap_results.json",
		"pipeline_steps.json",
	} {
		if ms, _ := filepath.Glob(pat); len(ms) > 0 {
			for _, m := range ms {
				if i, err := os.Stat(m); err == nil {
					logx.OK("  %s (%d bytes)", m, i.Size())
				}
			}
		}
	}
	logx.Head(fmt.Sprintf("\n═══ Pipeline complete (%s) ═══",
		time.Since(pipelineStart).Round(time.Millisecond)))
}

func hasCreds(files ...string) bool {
	for _, f := range files {
		if len(cfg.ReadLines(f)) > 0 {
			return true
		}
	}
	return false
}
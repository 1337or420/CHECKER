// cmd/nmap — nmap scanner → nmap_results.json.
// Из scripts/nmap_scanner.go, фикс: nmap.go удалён.
package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"runner/internal/cfg"
	"runner/internal/logx"
)

type nmapCfg struct {
	Enabled      bool   `json:"nmap_enabled"`
	Mode         string `json:"nmap_mode"`
	Timing       int    `json:"nmap_timing"`
	Ports        string `json:"nmap_ports"`
	ExtraArgs    string `json:"nmap_extra_args"`
	Targets      string `json:"nmap_targets"`
	VersionScan  bool   `json:"nmap_version_scan"`
	OSDetect     bool   `json:"nmap_os_detect"`
	NoPing       bool   `json:"nmap_no_ping"`
	Scripts      string `json:"nmap_scripts"`
	MaxRate      int    `json:"nmap_max_rate"`
	HostTimeout  string `json:"nmap_host_timeout"`
	TotalTimeout int    `json:"nmap_total_timeout_min"`
}

var portPresets = map[string]string{
	"top100": "21,22,23,25,53,80,88,110,111,135,139,143,161,389,443,445,464,587,636,993,995,1433,1521,2049,3268,3269,3306,3389,5432,5900,5985,5986,6379,8080,8443,8888,9090,9200,27017",
	"top1000": "",
	"full":    "1-65535",
	"web":     "80,443,8080,8443,8000,8888,3000,5000,4443,9090",
	"smb":     "135,139,445,137,138,3268,3269",
	"rdp":     "3389,3388,3390",
	"ad":      "53,88,135,139,389,445,464,636,3268,3269,3389,5985,9389",
	"pentest": "21,22,23,25,53,80,88,110,135,139,143,161,389,443,445,464,636,993,1433,1521,2049,3268,3269,3306,3389,4443,5432,5900,5985,6379,8080,8443,9090,9200,27017",
}

func defaultCfg() nmapCfg {
	return nmapCfg{Enabled: true, Mode: "normal", Timing: 4, Ports: "top100", Targets: "routes", NoPing: true, HostTimeout: "15m", TotalTimeout: 90}
}

// ─── XML → JSON ───────────────────────────────────────────────────────────

type XRun struct {
	XMLName  xml.Name `xml:"nmaprun"`
	Scanner  string   `xml:"scanner,attr"`
	Args     string   `xml:"args,attr"`
	StartStr string   `xml:"startstr,attr"`
	EndStr   string   `xml:"endstr,attr"`
	Version  string   `xml:"version,attr"`
	ScanInfo struct {
		Type, Protocol, NumSvc, Services string
	} `xml:"scaninfo"`
	Hosts []XHost `xml:"host"`
	Stats struct {
		Finished struct{ Elapsed, Summary string } `xml:"finished"`
		Hosts    struct{ Up, Down, Total string } `xml:"hosts"`
	} `xml:"runstats"`
}

type XHost struct {
	Status struct{ State string `xml:"state,attr"` } `xml:"status"`
	Addresses []struct {
		Addr, AddrType, Vendor string
	} `xml:"address"`
	Hostnames struct {
		H []struct{ Name string `xml:"name,attr"` } `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []XPort `xml:"port"`
	} `xml:"ports"`
	OS struct {
		Matches []struct {
			Name     string `xml:"name,attr"`
			Accuracy string `xml:"accuracy,attr"`
			Classes  []struct {
				Type, Vendor, Family, Gen, Accuracy string
				CPEs []struct{ V string `xml:",chardata"` } `xml:"cpe"`
			} `xml:"osclass"`
		} `xml:"osmatch"`
	} `xml:"os"`
	Uptime struct {
		LastBoot string `xml:"lastboot,attr"`
	} `xml:"uptime"`
}

type XPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct{ State string `xml:"state,attr"` } `xml:"state"`
	Service  struct {
		Name, Product, Version, ExtraInfo, OSType, Tunnel, Conf string
		CPEs []struct{ V string `xml:",chardata"` } `xml:"cpe"`
	} `xml:"service"`
	Scripts []struct {
		ID, Output string
	} `xml:"script"`
}

type nmapResult struct {
	ScanInfo  map[string]interface{} `json:"scan_info"`
	Hosts     []jHost                `json:"hosts"`
	Stats     map[string]interface{} `json:"stats"`
	StartTime string                 `json:"start_time"`
	EndTime   string                 `json:"end_time"`
	Args      string                 `json:"args"`
	Mode      string                 `json:"mode"`
	Duration  string                 `json:"duration"`
	Summary   nmapSummary            `json:"summary"`
	UpHosts   int                    `json:"up_hosts"`
	OpenPorts int                    `json:"open_ports"`
}

type nmapSummary struct {
	TotalHosts int            `json:"total_hosts"`
	UpHosts    int            `json:"up_hosts"`
	TotalPorts int            `json:"total_ports"`
	OpenPorts  int            `json:"open_ports"`
	Services   map[string]int `json:"services"`
	OSTypes    map[string]int `json:"os_types"`
	SMBHosts   []string       `json:"smb_hosts"`
	LDAPHosts  []string       `json:"ldap_hosts"`
	RDPHosts   []string       `json:"rdp_hosts"`
	HTTPHosts  []string       `json:"http_hosts"`
}

type jHost struct {
	IP         string   `json:"ip"`
	Status     string   `json:"status"`
	Hostnames  []string `json:"hostnames"`
	Ports      []jPort  `json:"ports"`
	OS         string   `json:"os,omitempty"`
	OSAccuracy string   `json:"os_accuracy,omitempty"`
	Uptime     string   `json:"uptime,omitempty"`
}

type jPort struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Extra    string `json:"extra,omitempty"`
	Tunnel   string `json:"tunnel,omitempty"`
}

func convert(nr *XRun, mode, dur string) *nmapResult {
	r := &nmapResult{
		Args: nr.Args, StartTime: nr.StartStr, EndTime: nr.EndStr,
		Mode: mode, Duration: dur,
		ScanInfo: map[string]interface{}{
			"type": nr.ScanInfo.Type, "protocol": nr.ScanInfo.Protocol,
			"num_services": nr.ScanInfo.NumSvc, "services": nr.ScanInfo.Services,
			"scanner": nr.Scanner, "version": nr.Version,
		},
		Stats: map[string]interface{}{
			"elapsed": nr.Stats.Finished.Elapsed, "summary": nr.Stats.Finished.Summary,
			"up": nr.Stats.Hosts.Up, "down": nr.Stats.Hosts.Down, "total": nr.Stats.Hosts.Total,
		},
		Summary: nmapSummary{Services: map[string]int{}, OSTypes: map[string]int{}},
	}
	smb, ldap, rdp, http := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}

	for _, h := range nr.Hosts {
		jh := jHost{Status: h.Status.State, Hostnames: []string{}, Ports: []jPort{}}
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				jh.IP = a.Addr
			}
		}
		for _, hn := range h.Hostnames.H {
			jh.Hostnames = append(jh.Hostnames, hn.Name)
		}
		if len(h.OS.Matches) > 0 {
			m := h.OS.Matches[0]
			jh.OS = m.Name
			jh.OSAccuracy = m.Accuracy
			for _, c := range m.Classes {
				if c.Family != "" {
					r.Summary.OSTypes[c.Family]++
				}
			}
		}
		if h.Uptime.LastBoot != "" {
			jh.Uptime = h.Uptime.LastBoot
		}
		for _, p := range h.Ports.Ports {
			jp := jPort{
				Port: p.PortID, Protocol: p.Protocol, State: p.State.State,
				Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version,
				Extra: p.Service.ExtraInfo, Tunnel: p.Service.Tunnel,
			}
			if p.State.State == "open" {
				r.Summary.OpenPorts++
				if p.Service.Name != "" {
					r.Summary.Services[p.Service.Name]++
				}
				switch p.PortID {
				case "445", "139":
					smb[jh.IP] = true
				case "389", "636":
					ldap[jh.IP] = true
				case "3389":
					rdp[jh.IP] = true
				case "80", "443", "8080", "8443":
					http[jh.IP] = true
				}
			}
			r.Summary.TotalPorts++
			jh.Ports = append(jh.Ports, jp)
		}
		r.Summary.TotalHosts++
		if h.Status.State == "up" {
			r.Summary.UpHosts++
		}
		r.Hosts = append(r.Hosts, jh)
	}
	if r.Hosts == nil {
		r.Hosts = []jHost{}
	}
	r.UpHosts = r.Summary.UpHosts
	r.OpenPorts = r.Summary.OpenPorts
	for ip := range smb {
		r.Summary.SMBHosts = append(r.Summary.SMBHosts, ip)
	}
	for ip := range ldap {
		r.Summary.LDAPHosts = append(r.Summary.LDAPHosts, ip)
	}
	for ip := range rdp {
		r.Summary.RDPHosts = append(r.Summary.RDPHosts, ip)
	}
	for ip := range http {
		r.Summary.HTTPHosts = append(r.Summary.HTTPHosts, ip)
	}
	nn := func(s *[]string) {
		if *s == nil {
			*s = []string{}
		}
	}
	nn(&r.Summary.SMBHosts)
	nn(&r.Summary.LDAPHosts)
	nn(&r.Summary.RDPHosts)
	nn(&r.Summary.HTTPHosts)
	return r
}

func buildArgs(c nmapCfg) []string {
	args := []string{"-iL", "nmap_targets.txt", "-oX", "nmap_scan.xml", "--open"}
	T := fmt.Sprintf("-T%d", c.Timing)
	switch c.Mode {
	case "ping":
		args = append(args, "-sn", T)
	case "quick":
		args = append(args, "-F", T, "-sV", "--version-intensity", "2")
	case "normal":
		args = append(args, "-sS", "--top-ports", "1000", T, "-sV")
	case "full":
		args = append(args, "-sS", "--top-ports", "1000", T, "-A", "-v")
	case "stealth":
		args = append(args, "-sS", "-T2", "-n", "--top-ports", "1000")
	case "custom":
		if c.ExtraArgs != "" {
			args = append(args, strings.Fields(c.ExtraArgs)...)
			return args
		}
		args = append(args, "--top-ports", "1000", T, "-sV")
	default:
		args = append(args, "-sS", "--top-ports", "1000", T, "-sV")
	}
	if c.Ports != "" && c.Mode != "ping" {
		if pr, ok := portPresets[c.Ports]; ok && pr != "" {
			c.Ports = pr
		}
		var f []string
		skip := false
		for _, a := range args {
			if a == "--top-ports" || a == "-F" {
				skip = true
				continue
			}
			if skip {
				skip = false
				continue
			}
			f = append(f, a)
		}
		args = append(f, "-p", c.Ports)
	}
	if c.OSDetect {
		args = append(args, "-O")
	}
	if c.NoPing && c.Mode != "ping" {
		args = append(args, "-Pn")
	}
	if c.MaxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(c.MaxRate))
	}
	if c.HostTimeout != "" {
		args = append(args, "--host-timeout", c.HostTimeout)
	}
	if c.Mode != "stealth" {
		args = append(args, "-n")
	}
	if c.Scripts != "" {
		args = append(args, "--script", c.Scripts)
	}
	if c.ExtraArgs != "" && c.Mode != "custom" {
		args = append(args, strings.Fields(c.ExtraArgs)...)
	}
	return args
}

func main() {
	fmt.Println("═══ Nmap Scanner v3.0 ═══")
	start := time.Now()

	c := defaultCfg()
	if d, err := os.ReadFile("job_config.json"); err == nil {
		var w struct {
			Scan json.RawMessage `json:"scan"`
			Nmap nmapCfg         `json:"nmap"`
		}
		if json.Unmarshal(d, &w) == nil && w.Nmap.Mode != "" {
			c = w.Nmap
		}
	}
	if d, err := os.ReadFile("nmap_config.json"); err == nil {
		_ = json.Unmarshal(d, &c)
	}
	if c.Timing < 0 || c.Timing > 5 {
		c.Timing = 4
	}
	if c.TotalTimeout <= 0 {
		c.TotalTimeout = 90
	}

	if _, err := exec.LookPath("nmap"); err != nil {
		logx.Err("nmap not found")
		os.Exit(1)
	}

	// Цели
	var tgts []string
	switch c.Targets {
	case "dns":
		tgts = cfg.ReadLines("dns.txt")
	case "all":
		tgts = append(cfg.ReadLines("routes.txt"), cfg.ReadLines("dns.txt")...)
	case "routes", "":
		tgts = cfg.ReadLines("routes.txt")
	default:
		if _, err := os.Stat(c.Targets); err == nil {
			tgts = cfg.ReadLines(c.Targets)
		} else {
			tgts = strings.Split(c.Targets, ",")
		}
	}
	tgts = cfg.Uniq(tgts)
	if len(tgts) == 0 {
		logx.Warn("no targets")
		os.Exit(0)
	}
	cfg.WriteLines("nmap_targets.txt", tgts)

	a := buildArgs(c)
	logx.Info("mode=%s T%d targets=%d", c.Mode, c.Timing, len(tgts))
	logx.Info("cmd: nmap %s", strings.Join(a, " "))

	cmd := exec.Command("nmap", a...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		logx.Err("start: %v", err)
		os.Exit(1)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	to := time.Duration(c.TotalTimeout) * time.Minute
	select {
	case err := <-done:
		if err != nil {
			logx.Warn("nmap: %v", err)
		}
	case <-time.After(to):
		cmd.Process.Kill()
		<-done
		logx.Warn("nmap timeout %v", to)
	}
	el := time.Since(start).Round(time.Millisecond)

	xd, err := os.ReadFile("nmap_scan.xml")
	if err != nil {
		logx.Warn("no XML: %v", err)
		os.Exit(0)
	}
	var nr XRun
	if err := xml.Unmarshal(xd, &nr); err != nil {
		logx.Err("XML: %v", err)
		os.Exit(0)
	}
	res := convert(&nr, c.Mode, el.String())

	j, _ := json.MarshalIndent(res, "", "  ")
	os.WriteFile("nmap_results.json", j, 0644)

	if len(res.Summary.SMBHosts) > 0 {
		cfg.WriteLines("nmap_smb_hosts.txt", res.Summary.SMBHosts)
	}
	if len(res.Summary.LDAPHosts) > 0 {
		cfg.WriteLines("nmap_ldap_hosts.txt", res.Summary.LDAPHosts)
	}
	var up, op []string
	for _, h := range res.Hosts {
		if h.Status == "up" && h.IP != "" {
			up = append(up, h.IP)
		}
		for _, p := range h.Ports {
			if p.State == "open" {
				op = append(op, h.IP+":"+p.Port)
			}
		}
	}
	cfg.WriteLines("nmap_hosts_up.txt", up)
	cfg.WriteLines("nmap_open_ports.txt", op)

	if f, err := os.Create("nmap_brief.txt"); err == nil {
		w := bufio.NewWriter(f)
		for _, h := range res.Hosts {
			if h.Status != "up" {
				continue
			}
			for _, p := range h.Ports {
				if p.State != "open" {
					continue
				}
				l := fmt.Sprintf("%s:%s %s", h.IP, p.Port, p.Service)
				if p.Product != "" {
					l += " " + p.Product
				}
				if p.Version != "" {
					l += " " + p.Version
				}
				w.WriteString(l + "\n")
			}
		}
		w.Flush()
		f.Close()
	}

	logx.OK("nmap_results.json (%d bytes)", len(j))
	logx.Info("Hosts: %d up / %d | Ports: %d open / %d",
		res.Summary.UpHosts, res.Summary.TotalHosts, res.Summary.OpenPorts, res.Summary.TotalPorts)
	logx.Info("SMB:%d LDAP:%d RDP:%d HTTP:%d",
		len(res.Summary.SMBHosts), len(res.Summary.LDAPHosts),
		len(res.Summary.RDPHosts), len(res.Summary.HTTPHosts))
}
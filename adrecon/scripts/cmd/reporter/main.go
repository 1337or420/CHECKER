// cmd/reporter — сборка network_report_<domain>.json.
// Фиксы: min() совместимость, поиск и .json, и .txt (не только .txt).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"runner/internal/cfg"
	"runner/internal/logx"
)

type networkReport struct {
	Metadata    reportMeta            `json:"metadata"`
	VPN         reportVPN             `json:"vpn"`
	Network     reportNetwork         `json:"network"`
	NetworkMap  []nmapHost            `json:"network_map"`
	NmapSummary nmapSummaryReport     `json:"nmap_summary"`
	Nmap        json.RawMessage       `json:"nmap_result,omitempty"`
	NXC         json.RawMessage       `json:"nxc"`
	LDAPEnum    json.RawMessage       `json:"ldap_enum"`
	Kerbrute    json.RawMessage       `json:"kerbrute"`
	SQLMap      json.RawMessage       `json:"sqlmap"`
	Domains     reportDomains         `json:"domains"`
	Hosts       reportHosts           `json:"hosts"`
	Credentials reportCreds           `json:"credentials"`
	Shares      []string              `json:"shares"`
	Compromised reportPwn3d           `json:"compromised"`
	Summary     reportSummary         `json:"summary"`
	Findings    []criticalFinding     `json:"critical_findings"`
	Pipeline    reportPipeline        `json:"pipeline"`
	ConfigUsed  json.RawMessage       `json:"config_used,omitempty"`
}

type nmapHost struct {
	IP        string     `json:"ip"`
	Hostnames []string   `json:"hostnames"`
	Status    string     `json:"status"`
	OS        string     `json:"os,omitempty"`
	Tags      []string   `json:"tags"`
	Ports     []nmapPort `json:"ports"`
}

type nmapPort struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type nmapSummaryReport struct {
	TotalTargets int            `json:"total_targets"`
	HostsUp      int            `json:"hosts_up"`
	HostsDown    int            `json:"hosts_down"`
	OpenPorts    int            `json:"open_ports"`
	Duration     string         `json:"duration"`
	ServiceMap   map[string]int `json:"service_map"`
	OSMap        map[string]int `json:"os_map"`
	PortMap      map[string]int `json:"port_map"`
	SMBHosts     []string       `json:"smb_hosts"`
	LDAPHosts    []string       `json:"ldap_hosts"`
	RDPHosts     []string       `json:"rdp_hosts"`
	HTTPHosts    []string       `json:"http_hosts"`
	SSHHosts     []string       `json:"ssh_hosts"`
	MSSQLHosts   []string       `json:"mssql_hosts"`
	DCCandidates []string       `json:"dc_candidates"`
}

type reportMeta struct {
	GeneratedAt      string `json:"generated_at"`
	Version          string `json:"version"`
	Vendor           string `json:"vendor"`
	Group            string `json:"group"`
	PipelineDuration string `json:"pipeline_duration"`
}

type reportVPN struct {
	Raw             string   `json:"raw"`
	IP              string   `json:"ip"`
	Port            string   `json:"port"`
	Login           string   `json:"login"`
	RoutesReceived  []string `json:"routes_received"`
	DNSReceived     []string `json:"dns_received"`
	SplitDNSDomains []string `json:"split_dns_domains"`
}

type reportNetwork struct {
	Routes   []string `json:"routes"`
	DNS      []string `json:"dns"`
	AllIPs   []string `json:"all_ips"`
	SMBIPs   []string `json:"smb_ips"`
	LDAPIPs  []string `json:"ldap_ips"`
	SSHIPs   []string `json:"ssh_ips"`
	RDPIPs   []string `json:"rdp_ips"`
	WinRMIPs []string `json:"winrm_ips"`
	MSSQLIPs []string `json:"mssql_ips"`
	FTPIPs   []string `json:"ftp_ips"`
	VNCIPs   []string `json:"vnc_ips"`
	WMIIPs   []string `json:"wmi_ips"`
}

type reportDomains struct {
	LDAP []string `json:"ldap"`
	SMB  []string `json:"smb"`
	All  []string `json:"all"`
}

type reportHosts struct {
	LDAP  []map[string]string `json:"ldap"`
	SMB   []map[string]string `json:"smb"`
	SSH   []map[string]string `json:"ssh"`
	RDP   []map[string]string `json:"rdp"`
	WinRM []map[string]string `json:"winrm"`
	MSSQL []map[string]string `json:"mssql"`
	FTP   []map[string]string `json:"ftp"`
	VNC   []map[string]string `json:"vnc"`
	WMI   []map[string]string `json:"wmi"`
}

type reportCreds struct {
	SMBValid   []string `json:"smb_valid"`
	LDAPValid  []string `json:"ldap_valid"`
	SSHValid   []string `json:"ssh_valid"`
	RDPValid   []string `json:"rdp_valid"`
	WinRMValid []string `json:"winrm_valid"`
	MSSQLValid []string `json:"mssql_valid"`
	FTPValid   []string `json:"ftp_valid"`
	VNCValid   []string `json:"vnc_valid"`
	WMIValid   []string `json:"wmi_valid"`
}

type reportPwn3d struct {
	Entries []string `json:"entries"`
	Count   int      `json:"count"`
}

type criticalFinding struct {
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Count    int      `json:"count,omitempty"`
	Items    []string `json:"items,omitempty"`
}

type reportPipeline struct {
	Steps          []pipelineStep `json:"steps"`
	StepsCompleted []string       `json:"steps_completed"`
	StepsFailed    []string       `json:"steps_failed"`
	StepsSkipped   []string       `json:"steps_skipped"`
}

type pipelineStep struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration"`
	Error    string `json:"error,omitempty"`
}

type reportSummary struct {
	TotalHostsUp        int      `json:"total_hosts_up"`
	TotalIPs            int      `json:"total_ips"`
	TotalDomains        int      `json:"total_domains"`
	TotalUsersFound     int      `json:"total_users_found"`
	TotalValidCreds     int      `json:"total_valid_creds"`
	TotalShares         int      `json:"total_shares"`
	TotalPwned          int      `json:"total_pwned"`
	TotalVulns          int      `json:"total_vulns"`
	TotalKerberoastable int      `json:"total_kerberoastable"`
	TotalASREPRoastable int      `json:"total_asreproastable"`
	TotalKerbruteUsers  int      `json:"total_kerbrute_users"`
	TotalKerbruteCreds  int      `json:"total_kerbrute_creds"`
	HasPwned            bool     `json:"has_pwned"`
	ProtocolsScanned    []string `json:"protocols_scanned"`
	ValidSMB, ValidLDAP, ValidSSH, ValidRDP, ValidWinRM int
	ValidMSSQL, ValidFTP, ValidVNC, ValidWMI             int
	NmapHostsUp, NmapOpenPorts                           int
}

var extraProtos = []string{"ssh", "rdp", "winrm", "mssql", "ftp", "vnc", "wmi"}

func readJSON(fn string) json.RawMessage {
	d, err := os.ReadFile(fn)
	if err != nil || len(d) == 0 {
		return nil
	}
	var v interface{}
	if json.Unmarshal(d, &v) != nil {
		return nil
	}
	return d
}

func parseHostLine(l string) map[string]string {
	h := map[string]string{"raw": l}
	p := strings.Split(l, "|")
	for i, k := range []string{"ip", "port", "hostname", "domain", "os", "smbv1", "signing", "null_auth"} {
		if i < len(p) {
			h[k] = strings.TrimSpace(p[i])
		}
	}
	return h
}

func findPwn3d(files []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, fn := range files {
		for _, l := range cfg.ReadLines(fn) {
			if strings.Contains(l, "Pwn3d") && !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}

func truncHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	fmt.Println("═══ Reporter v7.0 ═══")

	vendor, group := "fortinet", "default"
	var configUsed json.RawMessage
	if d, err := os.ReadFile("job_config.json"); err == nil {
		configUsed = d
		var jc struct{ Vendor, Group string }
		if json.Unmarshal(d, &jc) == nil {
			if jc.Vendor != "" {
				vendor = jc.Vendor
			}
			if jc.Group != "" {
				group = jc.Group
			}
		}
	}

	pipelineDuration := "unknown"
	if d, err := os.ReadFile("pipeline_duration.txt"); err == nil {
		pipelineDuration = strings.TrimSpace(string(d))
	}

	vpnLines := cfg.ReadLines("input.txt")
	vpnLine := ""
	if len(vpnLines) > 0 {
		vpnLine = vpnLines[0]
	}
	vpnParts := strings.SplitN(vpnLine, ":", 4)
	vpn := reportVPN{
		Raw:             vpnLine,
		RoutesReceived:  cfg.ReadLines("routes.txt"),
		DNSReceived:     cfg.ReadLines("dns.txt"),
		SplitDNSDomains: cfg.ReadLines("split_dns_domains.txt"),
	}
	if len(vpnParts) >= 3 {
		vpn.IP, vpn.Port, vpn.Login = vpnParts[0], vpnParts[1], vpnParts[2]
	}
	if vpn.IP == "" {
		if d, err := os.ReadFile("job_config.json"); err == nil {
			var jc struct{ IP string `json:"ip"` }
			if json.Unmarshal(d, &jc) == nil {
				vpn.IP = jc.IP
			}
		}
	}

	ldapDomains := cfg.ReadLines("ldap_domains.txt")
	smbDomains := cfg.ReadLines("smb_domains.txt")
	allDomains := cfg.Uniq(ldapDomains, smbDomains)

	smbIPs := cfg.ReadLines("smb_ips.txt")
	ldapIPs := cfg.ReadLines("ldap_ips.txt")
	pIPs := map[string][]string{}
	for _, p := range extraProtos {
		pIPs[p] = cfg.ReadLines(p + "_ips.txt")
	}
	allIPs := cfg.Uniq(smbIPs, ldapIPs)
	for _, p := range extraProtos {
		allIPs = cfg.Uniq(allIPs, pIPs[p])
	}

	smbValid := cfg.ReadLines("smb_valid.txt")
	ldapValid := cfg.ReadLines("ldap_valid.txt")
	pValid := map[string][]string{}
	for _, p := range extraProtos {
		pValid[p] = cfg.ReadLines(p + "_valid.txt")
	}

	shares := cfg.ReadLines("smb_shares.txt")

	pwnFiles := []string{"ldap_valid.txt", "smb_valid.txt", "ldap_hosts.txt", "smb_hosts.txt"}
	for _, p := range extraProtos {
		pwnFiles = append(pwnFiles, p+"_valid.txt")
	}
	pwn3d := findPwn3d(pwnFiles)

	var ldapHosts, smbHosts []map[string]string
	for _, l := range cfg.ReadLines("ldap_hosts.txt") {
		ldapHosts = append(ldapHosts, parseHostLine(l))
	}
	for _, l := range cfg.ReadLines("smb_hosts.txt") {
		smbHosts = append(smbHosts, parseHostLine(l))
	}
	pHosts := map[string][]map[string]string{}
	for _, p := range extraProtos {
		for _, l := range cfg.ReadLines(p + "_hosts.txt") {
			pHosts[p] = append(pHosts[p], parseHostLine(l))
		}
	}

	domain := "unknown"
	if len(ldapDomains) > 0 {
		domain = ldapDomains[0]
	} else if len(smbDomains) > 0 {
		domain = smbDomains[0]
	}

	totalValidCreds := len(smbValid) + len(ldapValid)
	for _, p := range extraProtos {
		totalValidCreds += len(pValid[p])
	}
	totalHosts := len(ldapHosts) + len(smbHosts)
	for _, p := range extraProtos {
		totalHosts += len(pHosts[p])
	}

	var protocolsScanned []string
	if len(smbValid) > 0 || len(smbHosts) > 0 {
		protocolsScanned = append(protocolsScanned, "smb")
	}
	if len(ldapValid) > 0 || len(ldapHosts) > 0 {
		protocolsScanned = append(protocolsScanned, "ldap")
	}
	for _, p := range extraProtos {
		if len(pValid[p]) > 0 || len(pHosts[p]) > 0 {
			protocolsScanned = append(protocolsScanned, p)
		}
	}

	r := networkReport{
		Metadata: reportMeta{
			GeneratedAt:      time.Now().Format(time.RFC3339),
			Version:          "7.0.0",
			Vendor:           vendor,
			Group:            group,
			PipelineDuration: pipelineDuration,
		},
		VPN: vpn,
		Network: reportNetwork{
			Routes: cfg.ReadLines("routes.txt"), DNS: cfg.ReadLines("dns.txt"),
			AllIPs: allIPs, SMBIPs: smbIPs, LDAPIPs: ldapIPs,
			SSHIPs: pIPs["ssh"], RDPIPs: pIPs["rdp"], WinRMIPs: pIPs["winrm"],
			MSSQLIPs: pIPs["mssql"], FTPIPs: pIPs["ftp"], VNCIPs: pIPs["vnc"], WMIIPs: pIPs["wmi"],
		},
		Domains: reportDomains{LDAP: ldapDomains, SMB: smbDomains, All: allDomains},
		Hosts: reportHosts{
			LDAP: ldapHosts, SMB: smbHosts,
			SSH: pHosts["ssh"], RDP: pHosts["rdp"], WinRM: pHosts["winrm"],
			MSSQL: pHosts["mssql"], FTP: pHosts["ftp"], VNC: pHosts["vnc"], WMI: pHosts["wmi"],
		},
		Credentials: reportCreds{
			SMBValid: smbValid, LDAPValid: ldapValid,
			SSHValid: pValid["ssh"], RDPValid: pValid["rdp"], WinRMValid: pValid["winrm"],
			MSSQLValid: pValid["mssql"], FTPValid: pValid["ftp"], VNCValid: pValid["vnc"], WMIValid: pValid["wmi"],
		},
		Shares:      shares,
		Compromised: reportPwn3d{Entries: pwn3d, Count: len(pwn3d)},
		ConfigUsed:  configUsed,
	}

	// Embed Nmap
	if d := readJSON("nmap_results.json"); d != nil {
		r.Nmap = d
		var nd struct {
			Hosts []struct {
				IP        string   `json:"ip"`
				Status    string   `json:"status"`
				Hostnames []string `json:"hostnames"`
				OS        string   `json:"os"`
				Ports     []struct {
					Port, Protocol, State, Service, Product, Version string
				} `json:"ports"`
			} `json:"hosts"`
			Summary struct {
				UpHosts   int            `json:"up_hosts"`
				OpenPorts int            `json:"open_ports"`
				TotalHosts int           `json:"total_hosts"`
				TotalPorts int           `json:"total_ports"`
				Services  map[string]int `json:"services"`
				OSTypes   map[string]int `json:"os_types"`
				SMBHosts  []string       `json:"smb_hosts"`
				LDAPHosts []string       `json:"ldap_hosts"`
				RDPHosts  []string       `json:"rdp_hosts"`
				HTTPHosts []string       `json:"http_hosts"`
			} `json:"summary"`
			Duration string `json:"duration"`
		}
		if json.Unmarshal(d, &nd) == nil {
			svcCount := map[string]int{}
			portCount := map[string]int{}
			osCount := map[string]int{}
			sshHosts := map[string]bool{}
			mssqlHosts := map[string]bool{}
			dcCand := map[string]bool{}
			for _, h := range nd.Hosts {
				if h.Status != "up" {
					continue
				}
				nh := nmapHost{IP: h.IP, Hostnames: h.Hostnames, Status: h.Status, OS: h.OS, Tags: []string{}, Ports: []nmapPort{}}
				if nh.Hostnames == nil {
					nh.Hostnames = []string{}
				}
				has88, has389, has445 := false, false, false
				for _, p := range h.Ports {
					if p.State != "open" {
						continue
					}
					nh.Ports = append(nh.Ports, nmapPort{Port: p.Port, Protocol: p.Protocol, State: p.State, Service: p.Service, Product: p.Product, Version: p.Version})
					svcCount[p.Service]++
					portCount[p.Port]++
					switch p.Port {
					case "22":
						sshHosts[h.IP] = true
					case "88":
						has88 = true
					case "389", "636":
						has389 = true
					case "445":
						has445 = true
					case "1433":
						mssqlHosts[h.IP] = true
					}
				}
				if has88 && has389 && has445 {
					nh.Tags = append(nh.Tags, "domain-controller")
					dcCand[h.IP] = true
				}
				if has445 {
					nh.Tags = append(nh.Tags, "smb")
				}
				if has389 {
					nh.Tags = append(nh.Tags, "ldap")
				}
				if sshHosts[h.IP] {
					nh.Tags = append(nh.Tags, "ssh")
				}
				if mssqlHosts[h.IP] {
					nh.Tags = append(nh.Tags, "mssql")
				}
				if h.OS != "" {
					osCount[h.OS]++
				}
				r.NetworkMap = append(r.NetworkMap, nh)
			}
			var dcList, sshList, mssqlList []string
			for ip := range dcCand {
				dcList = append(dcList, ip)
			}
			for ip := range sshHosts {
				sshList = append(sshList, ip)
			}
			for ip := range mssqlHosts {
				mssqlList = append(mssqlList, ip)
			}
			r.NmapSummary = nmapSummaryReport{
				TotalTargets: nd.Summary.TotalHosts,
				HostsUp:      nd.Summary.UpHosts,
				HostsDown:    nd.Summary.TotalHosts - nd.Summary.UpHosts,
				OpenPorts:    nd.Summary.OpenPorts,
				Duration:     nd.Duration,
				ServiceMap:   svcCount,
				OSMap:        osCount,
				PortMap:      portCount,
				SMBHosts:     nd.Summary.SMBHosts,
				LDAPHosts:    nd.Summary.LDAPHosts,
				RDPHosts:     nd.Summary.RDPHosts,
				HTTPHosts:    nd.Summary.HTTPHosts,
				SSHHosts:     sshList,
				MSSQLHosts:   mssqlList,
				DCCandidates: dcList,
			}
			r.Summary.NmapHostsUp = nd.Summary.UpHosts
			r.Summary.NmapOpenPorts = nd.Summary.OpenPorts
		}
	} else {
		logx.Warn("nmap_results.json not found")
	}
	if r.NetworkMap == nil {
		r.NetworkMap = []nmapHost{}
	}

	// NXC
	if d := readJSON("scan_result.json"); d != nil {
		r.NXC = d
		var s struct {
			Summary struct {
				TotalUsers, TotalVulns int
			} `json:"summary"`
		}
		if json.Unmarshal(d, &s) == nil {
			r.Summary.TotalUsersFound = s.Summary.TotalUsers
			r.Summary.TotalVulns = s.Summary.TotalVulns
		}
	}

	// LDAP enum
	if fs, _ := filepath.Glob("ldap_enum_report_*.json"); len(fs) > 0 {
		if d := readJSON(fs[0]); d != nil {
			r.LDAPEnum = d
			var ldap struct {
				Queries map[string]struct {
					Count int `json:"count"`
				} `json:"queries"`
			}
			if json.Unmarshal(d, &ldap) == nil {
				if q, ok := ldap.Queries["kerberoastable"]; ok && q.Count > r.Summary.TotalKerberoastable {
					r.Summary.TotalKerberoastable = q.Count
				}
				if q, ok := ldap.Queries["asreproastable"]; ok && q.Count > r.Summary.TotalASREPRoastable {
					r.Summary.TotalASREPRoastable = q.Count
				}
				if q, ok := ldap.Queries["all_users"]; ok && q.Count > r.Summary.TotalUsersFound {
					r.Summary.TotalUsersFound = q.Count
				}
			}
		}
	}

	// Kerbrute
	if d := readJSON("kerbrute_results.json"); d != nil {
		r.Kerbrute = d
		var kb struct {
			ValidUsers []string `json:"valid_users"`
			ValidCreds []struct{ User, Password string } `json:"valid_credentials"`
		}
		if json.Unmarshal(d, &kb) == nil {
			r.Summary.TotalKerbruteUsers = len(kb.ValidUsers)
			r.Summary.TotalKerbruteCreds = len(kb.ValidCreds)
			totalValidCreds += len(kb.ValidCreds)
		}
	}

	// SQLMap
	if d := readJSON("sqlmap_results.json"); d != nil {
		r.SQLMap = d
	}

	// Pipeline
	if d, err := os.ReadFile("pipeline_steps.json"); err == nil {
		var steps []pipelineStep
		if json.Unmarshal(d, &steps) == nil {
			r.Pipeline.Steps = steps
			for _, s := range steps {
				switch s.Status {
				case "ok":
					r.Pipeline.StepsCompleted = append(r.Pipeline.StepsCompleted, s.Name)
				case "failed":
					r.Pipeline.StepsFailed = append(r.Pipeline.StepsFailed, s.Name)
				case "skipped":
					r.Pipeline.StepsSkipped = append(r.Pipeline.StepsSkipped, s.Name)
				}
			}
		}
	}

	// Findings
	var findings []criticalFinding
	if len(pwn3d) > 0 {
		findings = append(findings, criticalFinding{
			Category: "cred", Severity: "critical",
			Title:  fmt.Sprintf("%d host(s) compromised (Pwn3d)", len(pwn3d)),
			Count:  len(pwn3d), Items: pwn3d,
		})
	}
	if r.Summary.TotalKerberoastable > 0 {
		findings = append(findings, criticalFinding{
			Category: "vuln", Severity: "high",
			Title: fmt.Sprintf("%d kerberoastable account(s)", r.Summary.TotalKerberoastable),
			Count: r.Summary.TotalKerberoastable,
		})
	}
	if r.Summary.TotalASREPRoastable > 0 {
		findings = append(findings, criticalFinding{
			Category: "vuln", Severity: "high",
			Title: fmt.Sprintf("%d ASREPRoastable account(s)", r.Summary.TotalASREPRoastable),
			Count: r.Summary.TotalASREPRoastable,
		})
	}
	if r.Summary.TotalKerbruteCreds > 0 {
		findings = append(findings, criticalFinding{
			Category: "cred", Severity: "critical",
			Title: fmt.Sprintf("%d valid credential(s) from Kerbrute", r.Summary.TotalKerbruteCreds),
			Count: r.Summary.TotalKerbruteCreds,
		})
	}
	r.Findings = findings

	// Summary
	r.Summary.TotalHostsUp = totalHosts
	r.Summary.TotalIPs = len(allIPs)
	r.Summary.TotalDomains = len(allDomains)
	r.Summary.TotalValidCreds = totalValidCreds
	r.Summary.TotalShares = len(shares)
	r.Summary.TotalPwned = len(pwn3d)
	r.Summary.HasPwned = len(pwn3d) > 0
	r.Summary.ProtocolsScanned = protocolsScanned
	r.Summary.ValidSMB = len(smbValid)
	r.Summary.ValidLDAP = len(ldapValid)
	r.Summary.ValidSSH = len(pValid["ssh"])
	r.Summary.ValidRDP = len(pValid["rdp"])
	r.Summary.ValidWinRM = len(pValid["winrm"])
	r.Summary.ValidMSSQL = len(pValid["mssql"])
	r.Summary.ValidFTP = len(pValid["ftp"])
	r.Summary.ValidVNC = len(pValid["vnc"])
	r.Summary.ValidWMI = len(pValid["wmi"])

	// Nil-safe
	if r.NetworkMap == nil {
		r.NetworkMap = []nmapHost{}
	}
	if r.Findings == nil {
		r.Findings = []criticalFinding{}
	}
	if r.Pipeline.Steps == nil {
		r.Pipeline.Steps = []pipelineStep{}
	}

	j, _ := json.MarshalIndent(r, "", "  ")
	name := fmt.Sprintf("network_report_%s.json", domain)
	os.WriteFile(name, j, 0644)
	logx.OK("%s (%d bytes)", name, len(j))

	fmt.Printf("\n══ Summary ══\n")
	fmt.Printf("  Hosts:%d IPs:%d Domains:%d\n", r.Summary.TotalHostsUp, r.Summary.TotalIPs, r.Summary.TotalDomains)
	fmt.Printf("  SMB:%d LDAP:%d SSH:%d RDP:%d MSSQL:%d WinRM:%d\n",
		r.Summary.ValidSMB, r.Summary.ValidLDAP, r.Summary.ValidSSH,
		r.Summary.ValidRDP, r.Summary.ValidMSSQL, r.Summary.ValidWinRM)
	fmt.Printf("  Shares:%d Pwn3d:%d Vulns:%d\n",
		r.Summary.TotalShares, r.Summary.TotalPwned, r.Summary.TotalVulns)
	fmt.Printf("  Users:%d Kerberoastable:%d ASREPRoastable:%d\n",
		r.Summary.TotalUsersFound, r.Summary.TotalKerberoastable, r.Summary.TotalASREPRoastable)
	fmt.Printf("  Kerbrute users:%d creds:%d\n",
		r.Summary.TotalKerbruteUsers, r.Summary.TotalKerbruteCreds)
	fmt.Printf("  Pipeline: %d ok, %d failed, %d skipped | Duration: %s\n",
		len(r.Pipeline.StepsCompleted), len(r.Pipeline.StepsFailed),
		len(r.Pipeline.StepsSkipped), pipelineDuration)
	_ = truncHead
}
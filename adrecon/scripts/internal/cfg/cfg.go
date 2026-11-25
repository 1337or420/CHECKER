// Package cfg — единый JobConfig для всех шагов.
// Читается из job_config.json, лежащего в /app/work.
package cfg

import (
	"encoding/json"
	"os"
	"strings"
)

type JobCred struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type KnownCred struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

type InputData struct {
	SkipVPN      bool        `json:"skip_vpn"`
	Targets      []string    `json:"targets"`
	DCIPs        []string    `json:"dc_ips"`
	Domain       string      `json:"domain"`
	DNSServers   []string    `json:"dns_servers"`
	UserListFile string      `json:"userlist_file"`
	PassListFile string      `json:"passlist_file"`
	ComboFile    string      `json:"combo_file"`
	KnownUsers   []string    `json:"known_users"`
	KnownCreds   []KnownCred `json:"known_creds"`
	SMBTargets   []string    `json:"smb_targets"`
	LDAPTargets  []string    `json:"ldap_targets"`
	ExcludeIPs   []string    `json:"exclude_ips"`
}

type PipelineConfig struct {
	Steps      []string `json:"steps"`
	SkipSteps  []string `json:"skip_steps"`
	StopOnFail []string `json:"stop_on_fail"`
}

type ScanCfg struct {
	Mode    string   `json:"mode"`
	Modules []string `json:"modules"`
	Timeout int      `json:"timeout_seconds"`
	Threads int      `json:"threads"`
}

type SQLMapCfg struct {
	Enabled       bool     `json:"enabled"`
	Targets       []string `json:"targets"`
	CustomCommand string   `json:"custom_command"`
}

type KerbruteCfg struct {
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

type FullJobConfig struct {
	// VPN
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Credentials []JobCred `json:"credentials"`
	Vendor      string    `json:"vendor"`
	Group       string    `json:"group"`

	InputData InputData      `json:"input_data"`
	Pipeline  PipelineConfig `json:"pipeline"`

	Nmap     json.RawMessage `json:"nmap"`
	NXC      json.RawMessage `json:"nxc"`
	Scan     ScanCfg         `json:"scan"`
	LDAPEnum json.RawMessage `json:"ldap_enum"`
	Kerbrute KerbruteCfg     `json:"kerbrute"`
	SQLMap   SQLMapCfg       `json:"sqlmap"`
	Report   json.RawMessage `json:"report"`
}

// Load читает job_config.json из рабочей директории.
// Env-переменные VPN_VENDOR/VPN_GROUP перекрывают.
func Load() FullJobConfig {
	var c FullJobConfig
	if d, err := os.ReadFile("job_config.json"); err == nil {
		_ = json.Unmarshal(d, &c)
	}
	if v := os.Getenv("VPN_VENDOR"); v != "" {
		c.Vendor = v
	}
	if g := os.Getenv("VPN_GROUP"); g != "" {
		c.Group = g
	}
	if c.Vendor == "" {
		c.Vendor = "fortinet"
	}
	if c.Group == "" {
		c.Group = "default"
	}
	if c.Scan.Timeout <= 0 {
		c.Scan.Timeout = 300
	}
	if c.Scan.Mode == "" {
		c.Scan.Mode = "full"
	}
	if c.Kerbrute.Threads <= 0 {
		c.Kerbrute.Threads = 20
	}
	if c.Kerbrute.Timeout <= 0 {
		c.Kerbrute.Timeout = 30
	}
	return c
}

// ReadLines — прочитать непустые строки без комментариев.
func ReadLines(fn string) []string {
	d, err := os.ReadFile(fn)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(d), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// WriteLines — записать построчно, права 0644.
func WriteLines(fn string, lines []string) {
	f, err := os.Create(fn)
	if err != nil {
		return
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
}

// Uniq — dedup с сохранением порядка.
func Uniq(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, v := range l {
			v = strings.TrimSpace(v)
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}
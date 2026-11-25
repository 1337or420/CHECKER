// cmd/ldapenum — глубокий LDAP-энум через ldapsearch.
// Фиксы: корректный bind (result:0), parseLDIF из internal/ldifx (base64+SID).
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"runner/internal/cfg"
	"runner/internal/ldifx"
	"runner/internal/logx"
)

// ─── Query registry ───────────────────────────────────────────────────────

type ldapQuery struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Filter      string   `json:"filter"`
	Attributes  []string `json:"attributes"`
	Category    string   `json:"category"`
	NXCFlag     string   `json:"nxc_flag"`
}

var queryRegistry = []ldapQuery{
	{"all_users", "All domain users",
		"(&(objectCategory=person)(objectClass=user))",
		[]string{"sAMAccountName", "displayName", "mail", "memberOf", "description", "lastLogon", "pwdLastSet", "userAccountControl", "whenCreated", "badPwdCount", "logonCount"},
		"users", ""},
	{"kerberoastable", "Kerberoastable users",
		"(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName", "servicePrincipalName", "memberOf", "description"},
		"security", "--kerberoasting"},
	{"asreproastable", "ASREPRoastable users",
		"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName", "memberOf", "description"},
		"security", "--asreproast asrep_hashes.txt"},
	{"admin_count", "AdminCount=1",
		"(&(objectCategory=user)(adminCount=1))",
		[]string{"sAMAccountName", "memberOf", "description", "adminCount"},
		"security", ""},
	{"pwd_never_expires", "Password never expires",
		"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
		[]string{"sAMAccountName", "displayName", "pwdLastSet", "lastLogon"},
		"security", ""},
	{"pwd_must_change", "Must change password",
		"(&(objectCategory=user)(pwdLastSet=0)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName", "displayName", "description"},
		"security", ""},
	{"near_lockout", "Near lockout (badPwdCount>=3)",
		"(&(objectCategory=user)(badPwdCount>=3))",
		[]string{"sAMAccountName", "badPwdCount", "lockoutTime"},
		"security", ""},
	{"pass_in_desc", "Password in description",
		"(&(objectCategory=user)(|(description=*pass*)(description=*pwd*)(description=*password*)(description=*cred*)(description=*secret*)))",
		[]string{"sAMAccountName", "description"},
		"security", ""},
	{"disabled_users", "Disabled accounts",
		"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
		[]string{"sAMAccountName", "displayName", "description"},
		"users", ""},
	{"unconstrained_users", "Unconstrained delegation (users)",
		"(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
		[]string{"sAMAccountName", "userAccountControl", "memberOf"},
		"security", ""},
	{"domain_admins", "Domain Admins members",
		"(&(objectCategory=group)(|(cn=Domain Admins)(cn=Admins du domaine)(cn=Domänen-Admins)))",
		[]string{"sAMAccountName", "member", "description"},
		"security", ""},
	{"enterprise_admins", "Enterprise/Schema Admins",
		"(&(objectCategory=group)(|(cn=Enterprise Admins)(cn=Schema Admins)))",
		[]string{"sAMAccountName", "member"},
		"security", ""},
	{"admin_groups", "Privileged groups (adminCount=1)",
		"(&(objectCategory=group)(adminCount=1))",
		[]string{"sAMAccountName", "member", "description"},
		"security", ""},
	{"all_groups", "All domain groups",
		"(objectCategory=group)",
		[]string{"sAMAccountName", "description", "groupType", "member"},
		"groups", "--groups"},
	{"domain_controllers", "Domain Controllers",
		"(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogon"},
		"computers", ""},
	{"all_computers", "All domain computers",
		"(sAMAccountType=805306369)",
		[]string{"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogon"},
		"computers", "--computers"},
	{"legacy_os", "Legacy OS",
		"(&(objectCategory=Computer)(|(operatingSystem=Windows XP*)(operatingSystem=Windows Vista*)(operatingSystem=Windows 7*)(operatingSystem=Windows Server 2003*)(operatingSystem=Windows Server 2008*)))",
		[]string{"sAMAccountName", "dNSHostName", "operatingSystem"},
		"security", ""},
	{"unconstrained_computers", "Unconstrained delegation (computers)",
		"(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
		[]string{"sAMAccountName", "dNSHostName", "userAccountControl"},
		"security", ""},
	{"shadow_credentials", "Shadow credentials",
		"(msDS-KeyCredentialLink=*)",
		[]string{"sAMAccountName", "msDS-KeyCredentialLink"},
		"security", ""},
	{"all_spns", "All SPNs",
		"(&(servicePrincipalName=*)(!(objectClass=computer)))",
		[]string{"sAMAccountName", "servicePrincipalName", "objectClass"},
		"services", ""},
	{"mssql_spns", "MSSQL SPNs",
		"(servicePrincipalName=MSSQLSvc/*)",
		[]string{"sAMAccountName", "servicePrincipalName"},
		"services", ""},
	{"domain_trusts", "Domain trusts",
		"(objectClass=trustedDomain)",
		[]string{"cn", "trustDirection", "trustType", "trustAttributes", "flatName"},
		"policy", ""},
	{"gpo_list", "GPOs",
		"(objectClass=groupPolicyContainer)",
		[]string{"displayName", "gPCFileSysPath", "flags", "versionNumber"},
		"policy", ""},
	{"password_policy", "Fine-Grained Password Policies",
		"(objectClass=msDS-PasswordSettings)",
		[]string{"cn", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold", "msDS-PasswordHistoryLength"},
		"policy", ""},
	{"constrained_delegation", "Constrained delegation",
		"(msDS-AllowedToDelegateTo=*)",
		[]string{"sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl", "objectClass", "memberOf"},
		"security", ""},
	{"rbcd_targets", "RBCD targets",
		"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
		[]string{"sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass"},
		"security", ""},
	{"laps_passwords", "LAPS readable",
		"(ms-Mcs-AdmPwd=*)",
		[]string{"sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "dNSHostName"},
		"security", ""},
	{"gmsa_accounts", "gMSA accounts",
		"(objectClass=msDS-GroupManagedServiceAccount)",
		[]string{"sAMAccountName", "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval", "servicePrincipalName"},
		"security", ""},
	{"machine_quota", "Machine Account Quota",
		"(objectClass=domain)",
		[]string{"ms-DS-MachineAccountQuota", "distinguishedName"},
		"security", ""},
	{"dnsadmins_members", "DnsAdmins members",
		"(&(objectClass=group)(cn=DnsAdmins))",
		[]string{"member", "cn"},
		"security", ""},
	{"exchange_groups", "Exchange security groups",
		"(&(objectClass=group)(|(cn=Exchange Windows Permissions)(cn=Organization Management)(cn=Exchange Trusted Subsystem)))",
		[]string{"cn", "member"},
		"security", ""},
	{"cert_templates_vuln", "ADCS templates",
		"(&(objectClass=pKICertificateTemplate)(!(msPKI-Enrollment-Flag:1.2.840.113556.1.4.803:=2)))",
		[]string{"cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "msPKI-Certificate-Application-Policy", "pKIExtendedKeyUsage", "nTSecurityDescriptor"},
		"security", ""},
	{"protected_users", "Protected Users group",
		"(&(objectClass=group)(cn=Protected Users))",
		[]string{"member", "cn"},
		"security", ""},
	{"sid_history", "SID History",
		"(sIDHistory=*)",
		[]string{"sAMAccountName", "sIDHistory", "objectClass", "memberOf"},
		"security", ""},
}

type ldapCred struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type ldapEnumConfig struct {
	LDAPHosts   []string   `json:"ldap_hosts"`
	Domain      string     `json:"domain"`
	BaseDN      string     `json:"base_dn"`
	Credentials []ldapCred `json:"credentials"`
	Queries     []string   `json:"queries"`
	UseTLS      bool       `json:"use_tls"`
	Timeout     int        `json:"timeout_seconds"`
	MaxResults  int        `json:"max_results"`
}

type queryResult struct {
	Name       string                   `json:"name"`
	Filter     string                   `json:"filter"`
	Count      int                      `json:"count"`
	Entries    []map[string]interface{} `json:"entries"`
	Error      string                   `json:"error,omitempty"`
	DurationMS int64                    `json:"duration_ms"`
	Method     string                   `json:"method"`
}

type ldapEnumResult struct {
	Host       string                 `json:"host"`
	Domain     string                 `json:"domain"`
	BaseDN     string                 `json:"base_dn"`
	Credential string                 `json:"credential"`
	Queries    map[string]queryResult `json:"queries"`
	Errors     []string               `json:"errors"`
	StartedAt  string                 `json:"started_at"`
	Duration   string                 `json:"duration"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

var reLDAPResult = regexp.MustCompile(`result:\s+(\d+)`)

func ldapResultOK(out string) bool {
	// Ищем ПОСЛЕДНИЙ result: — у ldapsearch их может быть несколько при paged results.
	all := reLDAPResult.FindAllStringSubmatch(out, -1)
	if len(all) == 0 {
		return false
	}
	for _, m := range all {
		if len(m) < 2 {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		if n != 0 && n != 4 { // 4 = size limit exceeded (нормально)
			return false
		}
	}
	return true
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(timeout):
		cmd.Process.Kill()
		<-done
		return buf.String(), fmt.Errorf("timeout after %v", timeout)
	}
}

// ─── ldapsearch ───────────────────────────────────────────────────────────

func ldapBind(host, domain, login, password string, useTLS bool, timeout int) (string, error) {
	port := 389
	scheme := "ldap"
	if useTLS {
		port = 636
		scheme = "ldaps"
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP unreachable %s:%d: %v", host, port, err)
	}
	c.Close()

	uri := fmt.Sprintf("%s://%s:%d", scheme, host, port)
	env := append(os.Environ(), "LDAPTLS_REQCERT=never")

	var cands []string
	if domain != "" {
		cands = append(cands, login+"@"+domain, domain+"\\"+login)
	}
	cands = append(cands, login)

	for _, bindDN := range cands {
		args := []string{"-x", "-H", uri, "-D", bindDN, "-w", password, "-b", "", "-s", "base", "-o", "ldif-wrap=no", "(objectClass=*)", "defaultNamingContext"}
		if useTLS {
			args = append([]string{"-o", "TLS_REQCERT=never"}, args...)
		}
		cmd := exec.Command("ldapsearch", args...)
		cmd.Env = env
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			continue
		}
		go func() { done <- cmd.Wait() }()
		var out string
		select {
		case <-done:
			out = buf.String()
		case <-time.After(time.Duration(timeout) * time.Second):
			cmd.Process.Kill()
			<-done
			continue
		}
		if ldapResultOK(out) {
			return bindDN, nil
		}
	}
	return "", fmt.Errorf("all bind attempts failed for %s", host)
}

func ldapGetBaseDN(host, bindDN, password string, useTLS bool, timeout int) string {
	scheme, port := "ldap", "389"
	if useTLS {
		scheme, port = "ldaps", "636"
	}
	uri := fmt.Sprintf("%s://%s:%s", scheme, host, port)
	args := []string{"-x", "-H", uri, "-D", bindDN, "-w", password, "-b", "", "-s", "base", "-o", "ldif-wrap=no", "(objectClass=*)", "defaultNamingContext", "namingContexts"}
	if useTLS {
		args = append([]string{"-o", "TLS_REQCERT=never"}, args...)
	}
	out, _ := func() (string, error) {
		cmd := exec.Command("ldapsearch", args...)
		cmd.Env = append(os.Environ(), "LDAPTLS_REQCERT=never")
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			return "", err
		}
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
			return buf.String(), nil
		case <-time.After(time.Duration(timeout) * time.Second):
			cmd.Process.Kill()
			<-done
			return "", fmt.Errorf("timeout")
		}
	}()
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		for _, p := range []string{"defaultNamingContext:", "namingContexts:"} {
			if strings.HasPrefix(line, p) {
				v := strings.TrimSpace(strings.TrimPrefix(line, p))
				if strings.HasPrefix(v, "DC=") {
					return v
				}
			}
		}
	}
	return ""
}

func ldapSearch(host, bindDN, password, baseDN, filter string, attrs []string, useTLS bool, timeout, maxResults int) (string, error) {
	scheme, port := "ldap", "389"
	if useTLS {
		scheme, port = "ldaps", "636"
	}
	uri := fmt.Sprintf("%s://%s:%s", scheme, host, port)
	args := []string{
		"-x", "-H", uri, "-D", bindDN, "-w", password, "-b", baseDN,
		"-z", fmt.Sprintf("%d", maxResults),
		"-E", "pr=1000/noprompt",
		"-o", "ldif-wrap=no",
		filter,
	}
	if useTLS {
		args = append([]string{"-o", "TLS_REQCERT=never"}, args...)
	}
	args = append(args, attrs...)

	cmd := exec.Command("ldapsearch", args...)
	cmd.Env = append(os.Environ(), "LDAPTLS_REQCERT=never")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	to := time.Duration(timeout*2) * time.Second
	select {
	case err := <-done:
		out := buf.String()
		if err != nil && !strings.Contains(out, "dn:") {
			return out, err
		}
		return out, nil
	case <-time.After(to):
		cmd.Process.Kill()
		<-done
		out := buf.String()
		if strings.Contains(out, "dn:") {
			return out, nil
		}
		return "", fmt.Errorf("timeout after %v", to)
	}
}

// ─── Config ───────────────────────────────────────────────────────────────

func buildEnumConfig() ldapEnumConfig {
	c := ldapEnumConfig{Timeout: 30, MaxResults: 5000}
	if d, err := os.ReadFile("ldap_enum_config.json"); err == nil {
		_ = json.Unmarshal(d, &c)
		return c
	}
	if ips := cfg.ReadLines("ldap_ips.txt"); len(ips) > 0 {
		c.LDAPHosts = ips
	} else if dns := cfg.ReadLines("dns.txt"); len(dns) > 0 {
		c.LDAPHosts = dns
	}
	var doms []string
	seen := map[string]bool{}
	for _, f := range []string{"ldap_domains.txt", "smb_domains.txt"} {
		for _, d := range cfg.ReadLines(f) {
			dl := strings.ToLower(strings.TrimSpace(d))
			if dl != "" && !seen[dl] {
				seen[dl] = true
				doms = append(doms, dl)
			}
		}
	}
	if len(doms) > 0 {
		c.Domain = doms[0]
	}

	credSeen := map[string]bool{}
	add := func(l, p string) {
		k := l + "|" + p
		if l != "" && !credSeen[k] {
			credSeen[k] = true
			c.Credentials = append(c.Credentials, ldapCred{l, p})
		}
	}
	for _, f := range []string{"ldap_valid.txt", "smb_valid.txt"} {
		for _, line := range cfg.ReadLines(f) {
			p := strings.SplitN(line, "|", 8)
			if len(p) >= 7 {
				add(p[5], p[6])
				if c.Domain == "" && p[4] != "" && strings.Contains(p[4], ".") {
					c.Domain = p[4]
				}
			}
		}
	}
	if d, err := os.ReadFile("job_config.json"); err == nil {
		var jc struct {
			Credentials []struct{ Login, Password string } `json:"credentials"`
		}
		if json.Unmarshal(d, &jc) == nil {
			for _, cc := range jc.Credentials {
				add(cc.Login, cc.Password)
			}
		}
	}
	if len(c.Credentials) == 0 {
		for _, line := range cfg.ReadLines("input.txt") {
			p := strings.SplitN(line, ":", 4)
			if len(p) >= 4 {
				add(p[2], p[3])
			}
		}
	}
	return c
}

func resolveQueries(names []string) []ldapQuery {
	if len(names) == 0 {
		return queryRegistry
	}
	byName := map[string]bool{}
	byCat := map[string]bool{}
	for _, n := range names {
		switch n {
		case "security", "users", "groups", "computers", "services", "policy":
			byCat[n] = true
		default:
			byName[n] = true
		}
	}
	var out []ldapQuery
	for _, q := range queryRegistry {
		if byName[q.Name] || byCat[q.Category] {
			out = append(out, q)
		}
	}
	if len(out) == 0 {
		return queryRegistry
	}
	return out
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_").Replace(s)
}

// ─── main ─────────────────────────────────────────────────────────────────

func main() {
	fmt.Println("\n\033[35m═══ LDAP Enumerator v7.0 ═══\033[0m")

	c := buildEnumConfig()
	if len(c.LDAPHosts) == 0 {
		logx.Err("No LDAP hosts")
		os.Exit(0)
	}
	if len(c.Credentials) == 0 {
		logx.Err("No credentials")
		os.Exit(0)
	}
	if c.BaseDN == "" && c.Domain != "" {
		c.BaseDN = domainToBaseDN(c.Domain)
	}
	if c.Timeout <= 0 {
		c.Timeout = 30
	}
	if c.MaxResults <= 0 {
		c.MaxResults = 5000
	}

	queries := resolveQueries(c.Queries)
	logx.Info("Hosts: %v", c.LDAPHosts)
	logx.Info("Domain: %s | BaseDN: %s", c.Domain, c.BaseDN)
	logx.Info("Creds: %d | Queries: %d", len(c.Credentials), len(queries))

	start := time.Now()
	result := &ldapEnumResult{
		Domain: c.Domain, BaseDN: c.BaseDN,
		StartedAt: start.Format(time.RFC3339),
		Queries:   map[string]queryResult{},
	}

	var bindDN, activeHost, activePass string
	var connected bool

	candDoms := []string{c.Domain}
	for _, f := range []string{"ldap_domains.txt", "smb_domains.txt"} {
		for _, d := range cfg.ReadLines(f) {
			dl := strings.ToLower(strings.TrimSpace(d))
			if dl != "" && dl != strings.ToLower(c.Domain) {
				candDoms = append(candDoms, dl)
			}
		}
	}

	for _, host := range c.LDAPHosts {
		if connected {
			break
		}
		for _, cred := range c.Credentials {
			if connected {
				break
			}
			for _, tryDom := range candDoms {
				if tryDom == "" {
					continue
				}
				logx.Info("[AUTH] %s on %s (domain=%s)", cred.Login, host, tryDom)
				bd, err := ldapBind(host, tryDom, cred.Login, cred.Password, c.UseTLS, c.Timeout)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s / %s@%s: %v", host, cred.Login, tryDom, err))
					logx.Warn("  [FAIL] %v", err)
					continue
				}
				bindDN = bd
				activeHost = host
				activePass = cred.Password
				result.Host = host
				result.Credential = cred.Login
				result.Domain = tryDom
				c.Domain = tryDom
				connected = true
				logx.OK("  bind as %s", bd)
				if c.BaseDN == "" || c.BaseDN != domainToBaseDN(tryDom) {
					c.BaseDN = ldapGetBaseDN(host, bd, cred.Password, c.UseTLS, c.Timeout)
					if c.BaseDN == "" {
						c.BaseDN = domainToBaseDN(tryDom)
					}
					result.BaseDN = c.BaseDN
					logx.Info("  BaseDN: %s", c.BaseDN)
				}
				break
			}
		}
	}

	if !connected {
		result.Errors = append(result.Errors, "no successful LDAP bind")
		logx.Err("Could not bind to any host")
	} else {
		logx.Info("Running %d queries against %s...", len(queries), activeHost)
		for _, q := range queries {
			fmt.Printf("  [Q] %-28s ", q.Name)
			qStart := time.Now()
			qr := queryResult{Name: q.Name, Filter: q.Filter}

			out, err := ldapSearch(activeHost, bindDN, activePass, c.BaseDN, q.Filter, q.Attributes, c.UseTLS, c.Timeout, c.MaxResults)
			qr.DurationMS = time.Since(qStart).Milliseconds()

			ldapOK := err == nil && ldapResultOK(out)
			if ldapOK {
				entries := ldifx.ParseLDIF(out)
				qr.Count = len(entries)
				qr.Entries = entries
				qr.Method = "ldapsearch"
				fmt.Printf("\033[32m%d entries\033[0m (%dms)\n", qr.Count, qr.DurationMS)
			} else {
				if err != nil {
					qr.Error = err.Error()
				} else {
					qr.Error = "ldap result error"
				}
				fmt.Printf("\033[31mERR\033[0m %s\n", qr.Error)
			}
			result.Queries[q.Name] = qr
		}
	}

	result.Duration = time.Since(start).Round(time.Millisecond).String()

	domPart := c.Domain
	if domPart == "" {
		domPart = activeHost
	}
	if domPart == "" {
		domPart = "unknown"
	}
	fname := fmt.Sprintf("ldap_enum_report_%s.json", sanitize(domPart))
	d, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(fname, d, 0644); err != nil {
		logx.Err("write report: %v", err)
	} else {
		logx.OK("%s (%d queries, %s)", fname, len(result.Queries), result.Duration)
	}
}
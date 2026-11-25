// Package nxcp — парсеры вывода NetExec (NXC).
// Поддерживает оба формата shares: старый (с префиксом SMB) и новый
// (табличный, без префикса). См. parseShares.
package nxcp

import (
	"regexp"
	"strings"
)

type ValidCred struct {
	Protocol, IP, Port, Hostname, Domain, Login, Password string
	Pwn3d, Guest                                          bool
}

type HostInfo struct {
	IP, Port, Hostname, Domain, OS, SMBv1, Signing, NullAuth string
}

type ShareInfo struct {
	IP, Hostname, ShareName, Permissions, Remark string
}

type RIDUser struct {
	IP, Hostname, Username, RID string
}

type VulnInfo struct {
	IP, Hostname, Port, Module, VulnName, Detail string
}

var (
	reNXC   = regexp.MustCompile(`^(SMB|LDAP|SSH|RDP|WinRM|MSSQL|FTP|VNC|WMI)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(\[.\])\s*(.*)`)
	reDom   = regexp.MustCompile(`(?i)domain[:\s]+([A-Za-z0-9.\-_]+\.[A-Za-z]{2,})`)
	reOS    = regexp.MustCompile(`(Windows[^()\[\]\n]+|Samba[^\s()\[\]\n]*|Linux[^\s()\[\]\n]*)`)
	reSMBv1 = regexp.MustCompile(`SMBv1[:\s]+(True|False|None)`)
	reSign  = regexp.MustCompile(`signing[:\s]+(True|False|None)`)
	reNull  = regexp.MustCompile(`Null Auth[:\s]+(True|False)`)
	rePwn   = regexp.MustCompile(`Pwn3d!`)
	reGuest = regexp.MustCompile(`\(Guest\)`)
	// Share: "ShareName  READ,WRITE  Remark" или "ShareName  Remark"
	reShareLine = regexp.MustCompile(`^(\S+)\s+(READ(?:,\s*WRITE)?|WRITE|NO ACCESS|)\s*(.*)$`)
	reRID       = regexp.MustCompile(`^(?:SMB|LDAP)\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+)\s+\[.\]?\s+(\S+)\s+\(RID:(\d+)\)`)
	reVuln      = regexp.MustCompile(`^(COERCE_PLUS|ZEROLOGON|NOPAC|SMBGHOST|PRINTNIG\S*|MS17-010|WEBDAV|SPOOLER)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+(.*)`)
)

// ParseHosts — из строк "SMB IP port HOST [*] info".
func ParseHosts(out, proto string) []HostInfo {
	seen := map[string]bool{}
	var r []HostInfo
	for _, l := range strings.Split(out, "\n") {
		m := reNXC.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) < 7 || m[1] != proto {
			continue
		}
		k := m[2] + "|" + m[4]
		if seen[k] {
			continue
		}
		seen[k] = true
		h := HostInfo{IP: m[2], Port: m[3], Hostname: m[4]}
		info := m[6]
		if d := reDom.FindStringSubmatch(info); len(d) > 1 {
			h.Domain = d[1]
		}
		if o := reOS.FindStringSubmatch(info); len(o) > 1 {
			h.OS = strings.TrimSpace(o[1])
		}
		if s := reSMBv1.FindStringSubmatch(info); len(s) > 1 {
			h.SMBv1 = s[1]
		}
		if s := reSign.FindStringSubmatch(info); len(s) > 1 {
			h.Signing = s[1]
		}
		if s := reNull.FindStringSubmatch(info); len(s) > 1 {
			h.NullAuth = s[1]
		}
		r = append(r, h)
	}
	return r
}

// ParseIPs — уникальные IP из строк протокола.
func ParseIPs(out, proto string) []string {
	var r []string
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		m := reNXC.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) >= 3 && m[1] == proto && !seen[m[2]] {
			seen[m[2]] = true
			r = append(r, m[2])
		}
	}
	return r
}

// ParseDoms — уникальные домены.
func ParseDoms(out, proto string) []string {
	var r []string
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		m := reNXC.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) < 7 || m[1] != proto {
			continue
		}
		if d := reDom.FindStringSubmatch(m[6]); len(d) > 1 {
			k := strings.ToLower(d[1])
			if !seen[k] {
				seen[k] = true
				r = append(r, k)
			}
		}
	}
	return r
}

// ParseValid — успешные аутентификации.
func ParseValid(out, proto, user, pass string) []ValidCred {
	seen := map[string]bool{}
	var r []ValidCred
	lines := strings.Split(out, "\n")
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		m := reNXC.FindStringSubmatch(l)
		if len(m) < 7 || m[1] != proto || m[5] != "[+]" {
			continue
		}
		k := proto + "|" + m[2] + "|" + user
		if seen[k] {
			continue
		}
		seen[k] = true
		vc := ValidCred{
			Protocol: proto, IP: m[2], Port: m[3], Hostname: m[4],
			Login: user, Password: pass,
			Pwn3d: rePwn.MatchString(l), Guest: reGuest.MatchString(l),
		}
		if d := reDom.FindStringSubmatch(m[6]); len(d) > 1 {
			vc.Domain = d[1]
		} else {
			// Ищем домен в предыдущих строках
			for j := i - 1; j >= 0 && j >= i-5; j-- {
				if strings.Contains(lines[j], m[2]) {
					if d2 := reDom.FindStringSubmatch(lines[j]); len(d2) > 1 {
						vc.Domain = d2[1]
						break
					}
				}
			}
		}
		r = append(r, vc)
	}
	return r
}

// ParseShares — из блока "[*] Enumerated shares".
// Пустая строка НЕ закрывает блок (NXC печатает пустые строки внутри).
// Блок закрывается на новом [+] / [-] / [*] или на строке с новым IP.
func ParseShares(out string) []ShareInfo {
	var r []ShareInfo
	inShares := false
	lastIP, lastHost := "", ""

	for _, raw := range strings.Split(out, "\n") {
		l := strings.TrimSpace(raw)
		if strings.Contains(l, "Enumerated shares") {
			inShares = true
			continue
		}
		if !inShares {
			continue
		}
		// Заголовок таблицы
		if strings.Contains(l, "Share") && strings.Contains(l, "Permissions") {
			continue
		}
		if strings.Contains(l, "-----") {
			continue
		}
		// Конец блока — служебный маркер другого типа
		if strings.HasPrefix(l, "[+]") || strings.HasPrefix(l, "[-]") {
			inShares = false
			continue
		}
		if l == "" {
			continue // пустая НЕ закрывает
		}

		// Полный формат со префиксом SMB IP port host
		if m := reNXC.FindStringSubmatch(l); len(m) >= 7 && m[1] == "SMB" {
			lastIP, lastHost = m[2], m[4]
			info := m[6]
			if sm := reShareLine.FindStringSubmatch(info); len(sm) >= 2 {
				r = append(r, ShareInfo{
					IP: m[2], Hostname: m[4],
					ShareName:   sm[1],
					Permissions: strings.TrimSpace(safe(sm, 2)),
					Remark:      strings.TrimSpace(safe(sm, 3)),
				})
			}
			continue
		}
		// Новый табличный формат: "ShareName  READ,WRITE  Remark"
		if m := reShareLine.FindStringSubmatch(l); len(m) >= 2 {
			r = append(r, ShareInfo{
				IP: lastIP, Hostname: lastHost,
				ShareName:   m[1],
				Permissions: strings.TrimSpace(safe(m, 2)),
				Remark:      strings.TrimSpace(safe(m, 3)),
			})
		}
	}
	return r
}

// ParseRIDUsers — строки "(RID:NNN)".
func ParseRIDUsers(out string) []RIDUser {
	var r []RIDUser
	for _, l := range strings.Split(out, "\n") {
		m := reRID.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) >= 5 {
			r = append(r, RIDUser{IP: m[1], Hostname: m[2], Username: m[3], RID: m[4]})
		}
	}
	return r
}

// ParseVulns — модули vuln, отбрасываем негативные.
func ParseVulns(out string) []VulnInfo {
	var r []VulnInfo
	for _, l := range strings.Split(out, "\n") {
		m := reVuln.FindStringSubmatch(strings.TrimSpace(l))
		if len(m) < 6 {
			continue
		}
		d := strings.TrimSpace(m[5])
		if strings.Contains(d, "[-]") || strings.Contains(d, "Error") {
			continue
		}
		if strings.Contains(d, "NOT") && strings.Contains(d, "vulnerable") {
			continue
		}
		if strings.Contains(d, "does NOT appear") {
			continue
		}
		vn := d
		if strings.Contains(d, "VULNERABLE") || strings.Contains(d, "Vulnerable") {
			if p := strings.SplitN(d, ",", 2); len(p) > 1 {
				vn = strings.TrimSpace(p[1])
			}
		}
		r = append(r, VulnInfo{IP: m[2], Port: m[3], Hostname: m[4], Module: m[1], VulnName: vn, Detail: d})
	}
	return r
}

// PasswordPolicy — из блока "Dumping password info".
type PasswordPolicy struct {
	Domain, MinLength, HistoryLength, MaxAge, MinAge string
	ComplexityFlags                                  string `json:"complexity_flags"`
	RefuseChange, StoreCleartext, LockoutAdmins      string
	NoClearChange, NoAnonChange, ComplexRequired     string
	LockoutThreshold, LockoutDuration, LockoutReset  string
	ForcedLogoff                                     string
}

func ParsePasswordPolicy(out string) (PasswordPolicy, bool) {
	var pp PasswordPolicy
	found := false
	ex := func(l, pfx string) string {
		i := strings.Index(l, pfx)
		if i < 0 {
			return ""
		}
		return strings.TrimSpace(l[i+len(pfx):])
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "Dumping password info") {
			found = true
			if v := ex(l, "domain:"); v != "" {
				pp.Domain = v
			}
			continue
		}
		if !found {
			continue
		}
		if v := ex(l, "Minimum password length:"); v != "" {
			pp.MinLength = v
		}
		if v := ex(l, "Password history length:"); v != "" {
			pp.HistoryLength = v
		}
		if v := ex(l, "Maximum password age:"); v != "" {
			pp.MaxAge = v
		}
		if v := ex(l, "Minimum password age:"); v != "" {
			pp.MinAge = v
		}
		if v := ex(l, "Password Complexity Flags:"); v != "" {
			pp.ComplexityFlags = v
		}
		if v := ex(l, "Domain Refuse Password Change:"); v != "" {
			pp.RefuseChange = v
		}
		if v := ex(l, "Domain Password Store Cleartext:"); v != "" {
			pp.StoreCleartext = v
		}
		if v := ex(l, "Domain Password Lockout Admins:"); v != "" {
			pp.LockoutAdmins = v
		}
		if v := ex(l, "Domain Password No Clear Change:"); v != "" {
			pp.NoClearChange = v
		}
		if v := ex(l, "Domain Password No Anon Change:"); v != "" {
			pp.NoAnonChange = v
		}
		if v := ex(l, "Domain Password Complex:"); v != "" {
			pp.ComplexRequired = v
		}
		if v := ex(l, "Account Lockout Threshold:"); v != "" {
			pp.LockoutThreshold = v
		}
		if v := ex(l, "Locked Account Duration:"); v != "" {
			pp.LockoutDuration = v
		}
		if v := ex(l, "Reset Account Lockout Counter:"); v != "" {
			pp.LockoutReset = v
		}
		if v := ex(l, "Forced Log off Time:"); v != "" {
			pp.ForcedLogoff = v
		}
	}
	return pp, found
}

func safe(m []string, i int) string {
	if i < len(m) {
		return m[i]
	}
	return ""
}
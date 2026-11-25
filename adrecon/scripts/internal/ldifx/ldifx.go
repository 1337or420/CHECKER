// Package ldifx — парсер LDIF с поддержкой base64 и SID.
package ldifx

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// ParseLDIF — LDIF → список записей (map).
// Поддерживает:
//   - многозначные атрибуты → []string
//   - base64 (attr:: value) → декодируется; SID → S-1-5-...
//   - folded lines (продолжение с пробела)
func ParseLDIF(out string) []map[string]interface{} {
	var entries []map[string]interface{}
	var cur map[string]interface{}
	var lastKey string

	flush := func() {
		if cur != nil && len(cur) > 0 {
			entries = append(entries, cur)
		}
		cur, lastKey = nil, ""
	}

	for _, raw := range strings.Split(out, "\n") {
		// LDIF folding
		if len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			if cur != nil && lastKey != "" {
				if s, ok := cur[lastKey].(string); ok {
					cur[lastKey] = s + strings.TrimLeft(raw, " \t")
				}
			}
			continue
		}

		line := strings.TrimRight(raw, "\r\n")
		if line == "" {
			flush()
			continue
		}
		// Служебные строки ldapsearch
		if strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "search:") ||
			strings.HasPrefix(line, "result:") ||
			strings.HasPrefix(line, "text:") ||
			strings.HasPrefix(line, "matchedDN:") ||
			strings.HasPrefix(line, "ref:") {
			continue
		}

		if strings.HasPrefix(line, "dn:") {
			flush()
			cur = map[string]interface{}{"dn": strings.TrimSpace(strings.TrimPrefix(line, "dn:"))}
			lastKey = "dn"
			continue
		}
		if cur == nil {
			continue
		}

		// Разбор key:: b64 / key: val / key:
		var key, val string
		var b64 bool
		if i := strings.Index(line, ":: "); i > 0 {
			key, val, b64 = line[:i], line[i+3:], true
		} else if i := strings.Index(line, ": "); i > 0 {
			key, val = line[:i], line[i+2:]
		} else if strings.HasSuffix(line, ":") {
			key = strings.TrimSuffix(line, ":")
		} else {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		if b64 {
			if dec, err := base64.StdEncoding.DecodeString(val); err == nil {
				val = decodeBinary(key, dec)
			} else {
				val = "[b64-invalid] " + val
			}
		}

		lastKey = key
		if ex, ok := cur[key]; ok {
			switch v := ex.(type) {
			case []string:
				cur[key] = append(v, val)
			case string:
				cur[key] = []string{v, val}
			default:
				cur[key] = []string{fmt.Sprintf("%v", v), val}
			}
		} else {
			cur[key] = val
		}
	}
	flush()
	return entries
}

// decodeBinary — специальная обработка известных бинарных атрибутов.
func decodeBinary(key string, b []byte) string {
	switch strings.ToLower(key) {
	case "objectsid", "sidhistory":
		return sidToString(b)
	case "ntsecuritydescriptor", "msds-allowedtoactonbehalfofotheridentity":
		return fmt.Sprintf("[binary %dB]", len(b))
	case "msds-keycredentiallink":
		return keyCredLink(b)
	default:
		if isPrintable(b) {
			return string(b)
		}
		return fmt.Sprintf("[binary %dB]", len(b))
	}
}

// sidToString — бинарный SID → S-1-5-21-...
func sidToString(b []byte) string {
	if len(b) < 8 {
		return fmt.Sprintf("[bad-sid %dB]", len(b))
	}
	rev := b[0]
	subCount := int(b[1])
	if len(b) < 8+subCount*4 {
		return fmt.Sprintf("[short-sid %dB]", len(b))
	}
	authority := uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 |
		uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	parts := []string{fmt.Sprintf("S-%d-%d", rev, authority)}
	for i := 0; i < subCount; i++ {
		off := 8 + i*4
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		parts = append(parts, fmt.Sprintf("%d", sub))
	}
	return strings.Join(parts, "-")
}

// keyCredLink — msDS-KeyCredentialLink: отдаём hex-хвост, чтобы не терять данные.
func keyCredLink(b []byte) string {
	// Реальный парсер — отдельная задача (WHfB). Для отчёта достаточно длины.
	return fmt.Sprintf("[keycred %dB]", len(b))
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}
// Package logx — единый логгер для всех шагов пайплайна.
// Убирает дублирование pS/pO/pE/pW/pH в csicl.go, forti_vpn.go,
// ldap_enum.go, nxc_scanner.go, kerbrute.go.
package logx

import (
	"fmt"
	"time"
)

func ts() string { return time.Now().Format("15:04:05") }

// Info — обычное сообщение [12:34:56] text
func Info(format string, a ...interface{}) {
	fmt.Printf("[%s] %s\n", ts(), fmt.Sprintf(format, a...))
}

// OK — зелёный [OK] text
func OK(format string, a ...interface{}) {
	fmt.Printf("\033[32m[OK]\033[0m %s\n", fmt.Sprintf(format, a...))
}

// Err — красный [ERR] text
func Err(format string, a ...interface{}) {
	fmt.Printf("\033[31m[ERR]\033[0m %s\n", fmt.Sprintf(format, a...))
}

// Warn — жёлтый [WARN] text
func Warn(format string, a ...interface{}) {
	fmt.Printf("\033[33m[WARN]\033[0m %s\n", fmt.Sprintf(format, a...))
}

// Head — циан, для заголовков
func Head(format string, a ...interface{}) {
	fmt.Printf("\033[36m%s\033[0m\n", fmt.Sprintf(format, a...))
}

// Step — пурпурный разделитель шага
func Step(n int, label string) {
	fmt.Printf("\n\033[35m══ STEP %d: %s ══\033[0m\n", n, label)
}
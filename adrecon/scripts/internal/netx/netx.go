// Package netx — работа с интерфейсами, TCP-пробами, tun.
package netx

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// PortOpen — TCP probe.
func PortOpen(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ActiveTunIface — первый up tun/ppp/vpn интерфейс с приватным IPv4.
func ActiveTunIface() string {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		n := strings.ToLower(i.Name)
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		if !(strings.HasPrefix(n, "tun") || strings.HasPrefix(n, "ppp") || strings.HasPrefix(n, "vpn")) {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				return i.Name
			}
		}
	}
	return ""
}

// WaitTun — ждать появления tun до maxWait.
func WaitTun(maxWait time.Duration) (string, bool) {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if t := ActiveTunIface(); t != "" {
			time.Sleep(2 * time.Second) // дать маршрутам устояться
			return t, true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", false
}

// IsPrivateIP — RFC1918.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
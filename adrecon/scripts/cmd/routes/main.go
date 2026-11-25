// cmd/routes — сбор маршрутов из таблицы ядра.
package main

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"runner/internal/cfg"
	"runner/internal/logx"
	"runner/internal/netx"
)

func isPrivateCIDR(cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, pn, _ := net.ParseCIDR(p)
		if pn.Contains(n.IP) {
			return true
		}
	}
	return false
}

func parseKernelRoutes(iface string) []string {
	out, err := exec.Command("ip", "route").Output()
	if err != nil {
		logx.Warn("ip route failed: %v", err)
		return nil
	}
	reCIDR := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})`)
	seen := map[string]bool{}
	var routes []string
	for _, line := range strings.Split(string(out), "\n") {
		if iface != "" && !strings.Contains(line, " dev "+iface) {
			if !strings.Contains(line, " dev tun") && !strings.Contains(line, " dev ppp") {
				continue
			}
		}
		for _, m := range reCIDR.FindAllString(line, -1) {
			_, n, err := net.ParseCIDR(m)
			if err != nil {
				continue
			}
			ones, _ := n.Mask.Size()
			if ones < 8 || ones > 30 {
				continue
			}
			if !isPrivateCIDR(m) {
				continue
			}
			c := n.String()
			if !seen[c] {
				seen[c] = true
				routes = append(routes, c)
				logx.Info("[ROUTE] %s", c)
			}
		}
	}
	return routes
}

func main() {
	fmt.Println("═══ Route Parser v5.0 ═══")
	iface := netx.ActiveTunIface()
	if iface != "" {
		logx.Info("VPN interface: %s", iface)
	} else {
		logx.Warn("No tun/ppp up")
	}

	fresh := parseKernelRoutes(iface)
	if len(fresh) > 0 {
		cfg.WriteLines("routes.txt", fresh)
		logx.OK("routes.txt updated: %d entries", len(fresh))
		return
	}
	// Сохраняем то, что уже записал VPN
	if ex := cfg.ReadLines("routes.txt"); len(ex) > 0 {
		logx.Info("Kernel empty, keeping VPN routes: %d", len(ex))
		return
	}
	logx.Warn("No routes found anywhere")
}
package mgmtapi

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// privateIPv4Ranges are always DIRECT, hardcoded exactly like the Python
// original: loopback, RFC 1918 private ranges, and link-local.
var privateIPv4Ranges = []struct{ net, mask string }{
	{"127.0.0.0", "255.0.0.0"},
	{"10.0.0.0", "255.0.0.0"},
	{"172.16.0.0", "255.240.0.0"},
	{"192.168.0.0", "255.255.0.0"},
	{"169.254.0.0", "255.255.0.0"},
}

func (s *Server) handlePAC(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()

	host := cfg.PacProxyHost
	if host == "" {
		host = r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	// The PAC PROXY directive is an HTTP-proxy pointer, so it must name a
	// "regular" listener — PrimaryProxyPort would happily return a SOCKS5
	// port on socks5-only configurations (the Android default).
	port := cfg.PrimaryRegularProxyPort()

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	fmt.Fprint(w, renderPAC(host, port, cfg.PacDirectHosts, cfg.PacDirectIPs))
}

func renderPAC(proxyHost string, proxyPort int, directHosts, directIPs []string) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n\n")

	b.WriteString("  if (isPlainHostName(host) || host === \"localhost\" || shExpMatch(host, \"*.local\")) {\n")
	b.WriteString("    return \"DIRECT\";\n  }\n\n")

	b.WriteString("  if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {\n")
	for _, rng := range privateIPv4Ranges {
		fmt.Fprintf(&b, "    if (isInNet(host, %q, %q)) { return \"DIRECT\"; }\n", rng.net, rng.mask)
	}
	for _, entry := range directIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, ":") {
			continue // IPv6 handled outside the IPv4-literal guard, below
		}
		netAddr, mask, ok := ipv4CIDRToNetmask(entry)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "    if (isInNet(host, %q, %q)) { return \"DIRECT\"; }\n", netAddr, mask)
	}
	b.WriteString("  }\n\n")

	for _, entry := range directIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" || !strings.Contains(entry, ":") {
			continue
		}
		// PAC has no isInNet6 - IPv6 direct entries match by exact host string.
		addr := strings.SplitN(entry, "/", 2)[0]
		fmt.Fprintf(&b, "  if (host === %q) { return \"DIRECT\"; }\n", addr)
	}

	for _, entry := range directHosts {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "*") {
			fmt.Fprintf(&b, "  if (shExpMatch(host, %q)) { return \"DIRECT\"; }\n", entry)
		} else {
			fmt.Fprintf(&b, "  if (shExpMatch(host, %q) || shExpMatch(host, %q)) { return \"DIRECT\"; }\n", entry, "*."+entry)
		}
	}

	proxyDirective := fmt.Sprintf("PROXY %s:%d", proxyHost, proxyPort)
	fmt.Fprintf(&b, "\n  return %q;\n}\n", proxyDirective)
	return b.String()
}

// ipv4CIDRToNetmask converts "a.b.c.d/n" (or a bare IPv4 with implicit /32)
// into (network, dotted-decimal netmask) for PAC's isInNet(host, net, mask).
func ipv4CIDRToNetmask(entry string) (network, mask string, ok bool) {
	if !strings.Contains(entry, "/") {
		ip := net.ParseIP(entry)
		if ip == nil || ip.To4() == nil {
			return "", "", false
		}
		return ip.String(), "255.255.255.255", true
	}
	_, ipnet, err := net.ParseCIDR(entry)
	if err != nil || ipnet.IP.To4() == nil {
		return "", "", false
	}
	maskBytes := ipnet.Mask
	maskStr := fmt.Sprintf("%d.%d.%d.%d", maskBytes[0], maskBytes[1], maskBytes[2], maskBytes[3])
	return ipnet.IP.String(), maskStr, true
}

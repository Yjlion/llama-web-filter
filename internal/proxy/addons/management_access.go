package addons

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// ManagementAccess ensures the management server is always reachable
// through the filtering proxy. Registered first, before PolicyRouter, so
// it runs before any filtering addon can block management traffic.
// Ported from proxy/addons/management_access.py's request hook (the
// dns_request hook has no equivalent yet - this engine doesn't run a DNS
// listener, so pseudo-domain resolution for dns-mode/transparent/WireGuard
// deployments isn't wired up; those modes are unimplemented per
// HANDOFF.md anyway).
//
// Behavior:
//  1. Pseudo-domain redirect: if the request host matches mgmt_hostname
//     (default "web.filter"), respond with a 302 to the management UI.
//  2. Management passthrough: if the request targets the management
//     port AND the destination host is local/loopback (or the same
//     address the client used to reach the proxy), mark the flow
//     allowed+passthrough so no filtering addon can block it.
type ManagementAccess struct{}

func (ManagementAccess) Name() string { return "management_access" }

func (ManagementAccess) HandleRequest(fc *proxy.FlowContext) {
	// The redirect below points at the address the client reached *this*
	// proxy on. When another proxy owns the client connection (ICAP) that
	// address is not one the browser can reach, so the redirect would be a
	// dead end - leave management access to the front-end in that case.
	if fc.SkipsFrontendAddons() {
		return
	}
	settings := fc.Runtime.Settings()
	destHost := strings.ToLower(fc.Request.URL.Hostname())
	mgmtHostname := strings.ToLower(settings.MgmtHostname)
	if mgmtHostname == "" {
		mgmtHostname = "web.filter"
	}
	mgmtPort := settings.MgmtPort

	// --- 1. Pseudo-domain redirect ---
	if destHost == mgmtHostname {
		proxyIP := fc.ProxySockName
		if proxyIP == "" {
			proxyIP = "127.0.0.1"
		}
		if strings.Contains(proxyIP, ":") && !strings.HasPrefix(proxyIP, "[") {
			proxyIP = "[" + proxyIP + "]"
		}
		// The scheme has to follow mgmt_tls, or this redirect sends the
		// browser to http:// against a TLS listener and it lands on a
		// protocol error instead of the UI.
		scheme := "http"
		if settings.MgmtTLS {
			scheme = "https"
		}
		location := fmt.Sprintf("%s://%s:%d/", scheme, proxyIP, mgmtPort)
		fc.Response = &http.Response{
			StatusCode: http.StatusFound,
			Header: http.Header{
				"Location":     []string{location},
				"Content-Type": []string{"text/plain"},
			},
		}
		fc.ResponseBody = nil
		// Gate the flow so no downstream addon re-processes it - every
		// addon's request hook still runs after this (mirrors mitmproxy),
		// so without these flags doh_filter/url_filter would look up the
		// (non-resolvable) pseudo-domain and overwrite the 302.
		fc.URLAllowed = true
		fc.MitmPassthrough = true
		return
	}

	// --- 2. Management server passthrough ---
	reqPort := fc.Request.URL.Port()
	if reqPort == "" {
		if fc.Request.URL.Scheme == "https" {
			reqPort = "443"
		} else {
			reqPort = "80"
		}
	}
	if portNum, err := strconv.Atoi(reqPort); err == nil && portNum == mgmtPort {
		proxyIPRaw := strings.ToLower(fc.ProxySockName)
		if isLocalHost(destHost) || destHost == proxyIPRaw {
			fc.URLAllowed = true
			fc.MitmPassthrough = true
		}
	}
}

// isLocalHost reports whether host is a loopback or unspecified
// (all-interfaces) address.
func isLocalHost(host string) bool {
	h := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if idx := strings.IndexByte(h, '%'); idx != -1 {
		h = h[:idx]
	}
	addr := net.ParseIP(h)
	if addr == nil {
		return false
	}
	return addr.IsLoopback() || addr.IsUnspecified()
}

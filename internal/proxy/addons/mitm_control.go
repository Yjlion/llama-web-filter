package addons

import (
	"strings"

	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// MitmControl marks flows that should bypass filtering, ported from
// proxy/addons/mitm_control.py:
//
//   - Site-based "include" mode: if the policy only wants to MITM specific
//     sites, requests to non-listed sites that somehow made it through
//     (plain HTTP traffic - inclusion can't un-intercept TLS) pass
//     unmodified.
//   - User-Agent rules: skip filtering for matching (exclude) or
//     non-matching (include) clients. Like the site-include mode, this only
//     marks passthrough - it can't un-intercept an already-decrypted
//     connection, since the User-Agent isn't visible until after MITM.
type MitmControl struct{}

func (MitmControl) Name() string { return "mitm_control" }

func (MitmControl) HandleRequest(fc *proxy.FlowContext) {
	policy := fc.Policy
	if policy == nil {
		return
	}
	cfg := policy.Mitm

	if cfg.Mode == "include" && len(cfg.Sites) > 0 {
		host := fc.Request.URL.Hostname()
		if !proxy.DomainInList(host, cfg.Sites) {
			fc.MitmPassthrough = true
		}
	}

	if cfg.UAMode != "off" && len(cfg.UserAgents) > 0 {
		ua := fc.Request.Header.Get("User-Agent")
		matched := uaMatches(ua, cfg.UserAgents)
		if (cfg.UAMode == "exclude" && matched) || (cfg.UAMode == "include" && !matched) {
			fc.MitmPassthrough = true
		}
	}
}

// uaMatches reports whether ua contains any token (case-insensitive
// substring), ported from mitm_control.py's _ua_matches.
func uaMatches(ua string, tokens []string) bool {
	ua = strings.ToLower(ua)
	for _, t := range tokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && strings.Contains(ua, t) {
			return true
		}
	}
	return false
}

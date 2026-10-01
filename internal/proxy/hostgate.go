package proxy

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/categories"
	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// ErrBlockedByPolicy marks a tunnel refused by the connection-level gate
// rather than by an upstream dial failure. It travels through the tunnelReady
// callback so each front-end can answer in its own protocol: HTTP 403 for
// CONNECT, reply 0x02 ("connection not allowed by ruleset") for SOCKS5, and
// SOCKS4's generic 91 rejection.
var ErrBlockedByPolicy = errors.New("proxy: connection blocked by policy")

// blockedError carries the human-readable block reason alongside
// ErrBlockedByPolicy, so the refusal a client sees names the rule that fired.
type blockedError struct{ reason string }

func (e blockedError) Error() string { return e.reason }
func (e blockedError) Unwrap() error { return ErrBlockedByPolicy }

// HostVerdict is the connection-level filtering decision for a tunnel target,
// reached before anything is decrypted (and, on the blind-splice path, before
// anything can be decrypted at all).
type HostVerdict struct {
	Blocked   bool
	Reason    string
	Component string
}

// CategoryVerdict applies a policy's url_filter category rules to a hostname.
// Shared by the UrlFilter addon (full-URL request path) and HostFilterVerdict
// (connection path) so the two can never drift apart - categories are matched
// on the hostname alone in both.
func CategoryVerdict(cats *categories.Store, host string, cfg models.UrlFilterConfig) (blocked bool, reason string) {
	if len(cfg.Categories) == 0 || cats == nil {
		return false, ""
	}
	cat := cats.MatchAny(host, cfg.Categories)
	if cfg.Mode == models.UrlFilterModeWhitelist {
		// Only listed categories are allowed; block everything else.
		if cat == "" {
			return true, "Site not in an allowed category (whitelist)"
		}
		return false, ""
	}
	// blacklist: block domains that fall in a listed category.
	if cat != "" {
		return true, "Site category '" + cat + "' blocked by policy"
	}
	return false, ""
}

// HostFilterVerdict is the host-only subset of the UrlFilter addon, evaluated
// from a tunnel target before any request exists. It exists for blind-spliced
// hosts (mitm.mode=exclude), which return from handleTunnel before a single
// addon runs and would otherwise be unfilterable for every client.
//
// Two deliberate differences from the addon:
//
//   - Allow/block patterns containing '/' are skipped. Those are path patterns
//     and a hostname cannot decide them; applying them here would block whole
//     domains a user only meant to block one path of.
//   - There is no URLAllowed/MitmPassthrough flow state. The MITM include-mode
//     rule is re-checked directly so a host the addon path would mark
//     passthrough isn't blocked here instead.
func HostFilterVerdict(rt *state.Runtime, policy *models.Policy, host string) HostVerdict {
	if policy == nil || !policy.UrlFilter.Enabled {
		return HostVerdict{}
	}
	// Mirrors MitmControl: in include mode, a non-listed site is passthrough
	// and every filtering addon (UrlFilter included) skips it.
	if policy.Mitm.Mode == models.MitmModeInclude && len(policy.Mitm.Sites) > 0 &&
		!DomainInList(host, policy.Mitm.Sites) {
		return HostVerdict{}
	}

	cfg := policy.UrlFilter
	for _, pattern := range cfg.Allow {
		if isHostPattern(pattern) && HostMatches(host, pattern) {
			return HostVerdict{}
		}
	}
	for _, pattern := range cfg.Block {
		if isHostPattern(pattern) && HostMatches(host, pattern) {
			return HostVerdict{Blocked: true, Reason: "URL blocked by policy", Component: "url_filter"}
		}
	}

	var cats *categories.Store
	if rt != nil {
		cats = rt.Categories
	}
	if blocked, reason := CategoryVerdict(cats, host, cfg); blocked {
		return HostVerdict{Blocked: true, Reason: reason, Component: "url_filter"}
	}
	return HostVerdict{}
}

// isHostPattern reports whether pattern can be decided from a hostname alone.
func isHostPattern(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	return pattern != "" && !strings.Contains(pattern, "/")
}

// logConnectionBlock records a refused tunnel in the blocks table. Like
// logDNSBlock this writes no requests-table row: that one is written by
// RequestLogger from a FlowContext, and no flow ever exists for a connection
// refused before interception. A refused tunnel therefore shows up under
// ?kind=blocks only.
func (e *Engine) logConnectionBlock(v HostVerdict, host string, port int, policy *models.Policy, clientIP string) {
	slog.Info("proxy: refused tunnel", "component", v.Component, "host", host, "port", port, "reason", v.Reason)
	// Counted before the store check: a refusal happened whether or not
	// block logging is enabled, and webfilter_blocks_total should not
	// silently go flat when someone turns log_blocks off.
	metrics.Blocks.Inc(v.Component)
	if e.Runtime == nil || e.Runtime.Logs == nil {
		return
	}
	policyName := "unknown"
	if policy != nil {
		policyName = policy.Name
	}
	_ = e.Runtime.Logs.LogBlock(logstore.BlockEntry{
		TS:        time.Now().Unix(),
		Domain:    host,
		URL:       connectionURL(host, port),
		Reason:    v.Reason,
		Component: v.Component,
		Policy:    policyName,
		ClientIP:  clientIP,
	})
}

// connectionURL renders a tunnel target for the blocks log, using the scheme
// the port implies so the entry reads like the other rows in the table.
func connectionURL(host string, port int) string {
	switch port {
	case 443:
		return "https://" + host
	case dotPort:
		return "dot://" + host
	default:
		return "tcp://" + net.JoinHostPort(host, strconv.Itoa(port))
	}
}

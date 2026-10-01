package addons

import "github.com/yjlion/llama-web-filter/internal/proxy"

// UrlFilter blocks/allows URLs and domains, and blocks by shared category,
// ported from proxy/addons/url_filter.py's request hook.
type UrlFilter struct{}

func (UrlFilter) Name() string { return "url_filter" }

func (UrlFilter) HandleRequest(fc *proxy.FlowContext) {
	policy := fc.Policy
	if policy == nil || !policy.UrlFilter.Enabled {
		return
	}
	// Honor MITM passthrough (include-mode non-listed sites, User-Agent
	// rules): these flows skip all filtering, URL rules included. Without
	// this, matching clients would still be blocked here while every later
	// addon skips them.
	if fc.MitmPassthrough {
		return
	}

	cfg := policy.UrlFilter
	host := fc.Request.URL.Hostname()
	url := fc.Request.URL.String()

	// Custom allow/block lists take precedence over categories.
	for _, pattern := range cfg.Allow {
		if proxy.UrlMatches(host, url, pattern) {
			fc.URLAllowed = true
			return
		}
	}
	for _, pattern := range cfg.Block {
		if proxy.UrlMatches(host, url, pattern) {
			fc.Block("URL blocked by policy", "url_filter")
			return
		}
	}

	// Shared categories, applied per mode. The verdict itself lives in
	// proxy.CategoryVerdict because the connection-level host gate
	// (proxy.HostFilterVerdict, for blind-spliced hosts) must reach exactly
	// the same decision from a hostname alone.
	if len(cfg.Categories) > 0 {
		if blocked, reason := proxy.CategoryVerdict(fc.Runtime.Categories, host, cfg); blocked {
			fc.Block(reason, "url_filter")
			return
		}
	}
}

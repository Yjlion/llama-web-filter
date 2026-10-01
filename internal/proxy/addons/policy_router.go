// Package addons implements the concrete addon chain, ported one-to-one
// from proxy/addons/*.py, wired together by cmd/webfilter/runners.go into
// a proxy.Pipeline in the exact order proxy/main.py registers them.
package addons

import "github.com/yjlion/llama-web-filter/internal/proxy"

// PolicyRouter attaches a policy to every flow by matching the client IP
// (MAC -> exact IP -> CIDR -> catch-all, via state.Runtime.GetPolicy).
// Ported from proxy/addons/policy_router.py's request hook; the
// settings/policies loading and hot-reload machinery itself lives in
// internal/proxy/state, shared by every addon.
type PolicyRouter struct{}

func (PolicyRouter) Name() string { return "policy_router" }

func (PolicyRouter) HandleRequest(fc *proxy.FlowContext) {
	fc.Policy = fc.Runtime.GetPolicy(fc.ClientIP)
}

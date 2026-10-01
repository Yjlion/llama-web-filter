package addons

import (
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/neighbors"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
	"github.com/yjlion/llama-web-filter/internal/proxy"
)

// RuleEvaluator runs right after PolicyRouter and overlays the rules that
// apply to this client, time and site onto the matched policy, so every
// downstream addon reads one effective policy. Rules are the natural-
// language layer ("blur adult images for 10.10.10.10 from 10:00 to 17:00");
// see internal/policy/rules.
type RuleEvaluator struct{}

func (RuleEvaluator) Name() string { return "rule_evaluator" }

func (RuleEvaluator) HandleRequest(fc *proxy.FlowContext) {
	if fc.Runtime == nil || fc.Request == nil {
		return
	}
	doc := fc.Runtime.Rules()
	if len(doc.Rules) == 0 {
		return
	}
	policyName := ""
	base := fc.Policy
	if base == nil {
		// No policy matched the client: rules still apply, over defaults.
		p := fc.Runtime.DefaultPolicy()
		base = &p
	} else {
		policyName = base.Name
	}
	c := rules.Client{
		IP:     fc.ClientIP,
		Policy: policyName,
		Host:   strings.ToLower(fc.Request.URL.Hostname()),
		URL:    fc.Request.URL.String(),
		Now:    time.Now(),
	}
	if needsMAC(doc) {
		c.MAC = neighbors.Lookup(fc.ClientIP)
	}
	eff, used := rules.Apply(*base, doc.Rules, c, doc.Devices, proxy.UrlInList)
	if len(used) == 0 {
		return
	}
	fc.Policy = &eff
	fc.RulesApplied = used
}

// needsMAC reports whether any rule or device alias names a MAC address,
// so the neighbour lookup is only paid when it can matter.
func needsMAC(doc *rules.File) bool {
	isMAC := func(s string) bool { return strings.Count(s, ":") == 5 || strings.Count(s, "-") == 5 }
	for _, r := range doc.Rules {
		for _, s := range r.Match.Sources {
			if isMAC(s) {
				return true
			}
		}
	}
	for _, members := range doc.Devices {
		for _, m := range members {
			if isMAC(m) {
				return true
			}
		}
	}
	return false
}

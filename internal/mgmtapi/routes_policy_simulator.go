package mgmtapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/macutil"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/neighbors"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

func (s *Server) registerPolicySimulatorRoute(r chi.Router) {
	r.Post("/api/tools/policy-simulate", s.handlePolicySimulate)
}

type policySimulateRequest struct {
	ClientIP  string `json:"client_ip"`
	ClientMAC string `json:"client_mac"`
	URL       string `json:"url"`
	Method    string `json:"method"`
}

type policySimulateDecision struct {
	Component string `json:"component"`
	Action    string `json:"action"`
	Reason    string `json:"reason,omitempty"`
}

func (s *Server) handlePolicySimulate(w http.ResponseWriter, r *http.Request) {
	var payload policySimulateRequest
	_ = readJSON(r, &payload)
	clientIP := strings.TrimSpace(payload.ClientIP)
	if clientIP == "" {
		writeJSONError(w, http.StatusBadRequest, "client_ip is required")
		return
	}
	policies, err := s.Policies.List()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	lookupMAC := func(ip string) string {
		if mac := macutil.Normalize(payload.ClientMAC); mac != "" {
			return mac
		}
		return neighbors.Lookup(ip)
	}
	match := state.MatchPolicy(policies, clientIP, now, lookupMAC)
	response := map[string]any{
		"client_ip":     clientIP,
		"evaluated_at":  now.Format(time.RFC3339),
		"policy_match":  match,
		"schedule_note": scheduleNote(match),
	}
	if match.PolicyIndex < 0 {
		response["action"] = "no_policy"
		writeJSON(w, http.StatusOK, response)
		return
	}
	policy := policies[match.PolicyIndex]
	response["policy"] = policy.Name

	decisions, finalAction := s.simulatePolicyURL(r.Context(), policy, strings.TrimSpace(payload.URL))
	response["action"] = finalAction
	response["decisions"] = decisions
	writeJSON(w, http.StatusOK, response)
}

func scheduleNote(match state.PolicyMatch) string {
	if len(match.InactivePolicies) == 0 {
		return "all matching policies with schedules are active or unscheduled"
	}
	return "some policies were skipped because their schedules are inactive"
}

func (s *Server) simulatePolicyURL(ctx context.Context, policy models.Policy, rawURL string) ([]policySimulateDecision, string) {
	decisions := []policySimulateDecision{}
	finalAction := "ok"
	if rawURL == "" {
		return append(decisions, policySimulateDecision{Component: "policy_router", Action: "matched", Reason: "policy selected; no URL supplied for addon simulation"}), finalAction
	}
	parsed, err := parseSimulatorURL(rawURL)
	if err != nil {
		return append(decisions, policySimulateDecision{Component: "input", Action: "invalid", Reason: err.Error()}), "invalid"
	}
	host := parsed.Hostname()
	urlString := parsed.String()

	if policy.Mitm.Mode == models.MitmModeInclude && !matchesAnyURLPattern(host, urlString, policy.Mitm.Sites) {
		decisions = append(decisions, policySimulateDecision{Component: "mitm_control", Action: "passthrough", Reason: "MITM include mode does not list this host; downstream filters skip it"})
		return decisions, "passthrough"
	}

	urlDecision := s.simulateURLFilter(policy, host, urlString)
	decisions = append(decisions, urlDecision)
	if urlDecision.Action == "blocked" {
		return decisions, "blocked"
	}
	if urlDecision.Action == "allowed" {
		return decisions, "allowed"
	}
	if policy.CategoryFilter.Enabled {
		catDecision := s.simulateCategoryFilter(ctx, policy.CategoryFilter, host)
		decisions = append(decisions, catDecision)
		if catDecision.Action == "blocked" {
			return decisions, "blocked"
		}
	}

	if policy.Doh.Enabled {
		decisions = append(decisions, policySimulateDecision{Component: "doh_filter", Action: "would_inspect", Reason: "DoH filtering is enabled for this policy"})
	}
	if policy.SafeSearch.Enabled {
		decisions = append(decisions, policySimulateDecision{Component: "safesearch", Action: "would_modify", Reason: "SafeSearch may rewrite search URLs or block configured search tabs"})
	}
	if policy.YouTube.Enabled {
		decisions = append(decisions, policySimulateDecision{Component: "youtube", Action: "would_inspect", Reason: "YouTube filtering is enabled for this policy"})
	}
	if policy.TextClassifier.Enabled {
		decisions = append(decisions, policySimulateDecision{Component: "text_classifier", Action: "would_inspect_response", Reason: "text classifier runs after the response body is available"})
	}
	if policy.ImageClassifier.Enabled {
		decisions = append(decisions, policySimulateDecision{Component: "image_classifier", Action: "would_inspect_response", Reason: "image classifier runs after image or inline-image response content is available"})
	}
	return decisions, finalAction
}

// simulateCategoryFilter answers as a navigation to host would: it may ask
// the model, waiting a few seconds, since a person is waiting on a tool
// rather than a browser on a page.
func (s *Server) simulateCategoryFilter(ctx context.Context, cfg models.CategoryFilterConfig, host string) policySimulateDecision {
	const component = "category_filter"
	if s.Sites == nil {
		return policySimulateDecision{Component: component, Action: "unknown", Reason: "site categories are only available under `webfilter run`"}
	}
	ans := s.Sites.Categorize(ctx, state.CategoryLookup{Host: host, Enqueue: true, Budget: 8 * time.Second})
	if !ans.Known {
		action, fallback := "unknown", cfg.OnUnavailable
		reason := "the model is not available"
		if ans.TimedOut {
			fallback, reason = cfg.OnTimeout, "the model did not answer in time"
		}
		if fallback == models.FallbackBlock {
			action = "blocked"
		}
		return policySimulateDecision{Component: component, Action: action, Reason: reason + "; fallback " + string(fallback)}
	}
	label := sitecat.Label(ans.Category) + " (" + ans.Source + ")"
	if cfg.Blocks(ans.Category) {
		return policySimulateDecision{Component: component, Action: "blocked", Reason: "site category " + label}
	}
	return policySimulateDecision{Component: component, Action: "no_match", Reason: "site category " + label + " is allowed"}
}

func parseSimulatorURL(rawURL string) (*url.URL, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Hostname() == "" {
		return nil, url.InvalidHostError("missing host")
	}
	return parsed, nil
}

func (s *Server) simulateURLFilter(policy models.Policy, host, urlString string) policySimulateDecision {
	if !policy.UrlFilter.Enabled {
		return policySimulateDecision{Component: "url_filter", Action: "skipped", Reason: "URL filter is disabled"}
	}
	for _, pattern := range policy.UrlFilter.Allow {
		if proxy.UrlMatches(host, urlString, pattern) {
			return policySimulateDecision{Component: "url_filter", Action: "allowed", Reason: "matched allow pattern " + pattern}
		}
	}
	for _, pattern := range policy.UrlFilter.Block {
		if proxy.UrlMatches(host, urlString, pattern) {
			return policySimulateDecision{Component: "url_filter", Action: "blocked", Reason: "matched block pattern " + pattern}
		}
	}
	if len(policy.UrlFilter.Categories) == 0 {
		return policySimulateDecision{Component: "url_filter", Action: "no_match", Reason: "no URL allow/block/category rule matched"}
	}
	cat := s.Categories.MatchAny(host, policy.UrlFilter.Categories)
	if policy.UrlFilter.Mode == models.UrlFilterModeWhitelist {
		if cat == "" {
			return policySimulateDecision{Component: "url_filter", Action: "blocked", Reason: "site is not in an allowed category"}
		}
		return policySimulateDecision{Component: "url_filter", Action: "allowed", Reason: "matched allowed category " + cat}
	}
	if cat != "" {
		return policySimulateDecision{Component: "url_filter", Action: "blocked", Reason: "matched blocked category " + cat}
	}
	return policySimulateDecision{Component: "url_filter", Action: "no_match", Reason: "no URL allow/block/category rule matched"}
}

func matchesAnyURLPattern(host, urlString string, patterns []string) bool {
	for _, pattern := range patterns {
		if proxy.UrlMatches(host, urlString, pattern) {
			return true
		}
	}
	return false
}

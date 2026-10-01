package mgmtapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/neighbors"
	"github.com/yjlion/llama-web-filter/internal/policy/nlp"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// registerRulesRoutes wires the natural-language rules API:
//
//	GET    /api/rules                 the rules document (+ a summary per rule)
//	POST   /api/rules/compile         {text} -> compiled rule for confirmation
//	POST   /api/rules                 save a (compiled or hand-built) rule
//	PUT    /api/rules/{id}            replace a rule
//	DELETE /api/rules/{id}
//	POST   /api/rules/{id}/enable     {enabled}
//	PUT    /api/rules/devices         {devices}
//	GET    /api/rules/evaluate        ?client_ip=&url= -> rules that apply
func (s *Server) registerRulesRoutes(r chi.Router) {
	r.Get("/api/rules", s.handleGetRules)
	r.Get("/api/rules/evaluate", s.handleEvaluateRules)
	r.Post("/api/rules/compile", s.handleCompileRule)
	r.With(s.requireUnlocked).Post("/api/rules", s.handleAddRule)
	r.With(s.requireUnlocked).Put("/api/rules/devices", s.handleSetDevices)
	r.With(s.requireUnlocked).Put("/api/rules/{id}", s.handleUpdateRule)
	r.With(s.requireUnlocked).Delete("/api/rules/{id}", s.handleDeleteRule)
	r.With(s.requireUnlocked).Post("/api/rules/{id}/enable", s.handleEnableRule)
}

type ruleView struct {
	rules.Rule
	Summary string `json:"summary"`
}

func viewsOf(rs []rules.Rule) []ruleView {
	out := make([]ruleView, 0, len(rs))
	for _, r := range rs {
		out = append(out, ruleView{Rule: r, Summary: rules.Describe(r)})
	}
	return out
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	f, err := s.Rules.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":    f.Devices,
		"rules":      viewsOf(f.Rules),
		"targets":    rules.Targets,
		"actions":    rules.Actions,
		"llm_ready":  s.llmClient() != nil,
		"policies":   s.policyNames(),
		"categories": s.categoryNames(),
	})
}

func (s *Server) llmClient() *client.Client {
	if s.LLMClient == nil {
		return nil
	}
	return s.LLMClient()
}

func (s *Server) policyNames() []string {
	list, err := s.Policies.List()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(list))
	for _, p := range list {
		names = append(names, p.Name)
	}
	return names
}

func (s *Server) categoryNames() []string {
	var names []string
	for _, c := range s.Categories.List() {
		names = append(names, c.Name)
	}
	return names
}

func (s *Server) compiler() (*nlp.Compiler, map[string][]string, error) {
	f, err := s.Rules.Load()
	if err != nil {
		return nil, nil, err
	}
	return &nlp.Compiler{
		Client:     s.llmClient,
		Devices:    f.Devices,
		Policies:   s.policyNames(),
		Categories: s.categoryNames(),
	}, f.Devices, nil
}

func (s *Server) handleCompileRule(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Text string `json:"text"`
	}
	_ = readJSON(r, &payload)
	c, _, err := s.compiler()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	budget := time.Duration(s.Settings().LLM.Budget.CompileMs) * time.Millisecond
	if budget <= 0 {
		budget = time.Minute
	}
	ctx, cancel := contextWithTimeout(r, budget)
	defer cancel()
	out, err := c.Compile(ctx, payload.Text)
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var rule rules.Rule
	if err := readJSON(r, &rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid rule: "+err.Error())
		return
	}
	rule.ID = ""
	rule.Created = time.Time{}
	if !rule.Enabled && rule.Text == "" {
		rule.Enabled = true
	}
	saved, err := s.Rules.Add(rule)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{TS: time.Now().Unix(), Action: "rule_added", PolicyName: "rule:" + saved.ID, ClientIP: adminClientIP(r)})
	writeJSON(w, http.StatusCreated, ruleView{Rule: saved, Summary: rules.Describe(saved)})
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	var rule rules.Rule
	if err := readJSON(r, &rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid rule: "+err.Error())
		return
	}
	rule.ID = chi.URLParam(r, "id")
	saved, err := s.Rules.Update(rule)
	if errors.Is(err, rules.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{TS: time.Now().Unix(), Action: "rule_updated", PolicyName: "rule:" + saved.ID, ClientIP: adminClientIP(r)})
	writeJSON(w, http.StatusOK, ruleView{Rule: saved, Summary: rules.Describe(saved)})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.Rules.Delete(id)
	if errors.Is(err, rules.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{TS: time.Now().Unix(), Action: "rule_deleted", PolicyName: "rule:" + id, ClientIP: adminClientIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (s *Server) handleEnableRule(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	_ = readJSON(r, &payload)
	saved, err := s.Rules.SetEnabled(chi.URLParam(r, "id"), payload.Enabled)
	if errors.Is(err, rules.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ruleView{Rule: saved, Summary: rules.Describe(saved)})
}

func (s *Server) handleSetDevices(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Devices map[string][]string `json:"devices"`
	}
	if err := readJSON(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := s.Rules.SetDevices(payload.Devices); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	f, _ := s.Rules.Load()
	writeJSON(w, http.StatusOK, map[string]any{"devices": f.Devices})
}

// handleEvaluateRules answers "which rules apply to this client on this
// URL right now", with the effective policy's headline switches, for the
// Rules page's tester.
func (s *Server) handleEvaluateRules(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.TrimSpace(r.URL.Query().Get("client_ip"))
	raw := strings.TrimSpace(r.URL.Query().Get("url"))
	if clientIP == "" {
		writeJSONError(w, http.StatusBadRequest, "client_ip is required")
		return
	}
	if raw == "" {
		raw = "https://example.com/"
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad url")
		return
	}
	f, err := s.Rules.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policies, _ := s.Policies.List()
	match := state.MatchPolicy(policies, clientIP, time.Now(), neighbors.Lookup)
	base := policyByName(policies, "default")
	policyName := ""
	if match.PolicyIndex >= 0 {
		base = policies[match.PolicyIndex]
		policyName = base.Name
	}
	c := rules.Client{IP: clientIP, MAC: neighbors.Lookup(clientIP), Policy: policyName, Host: strings.ToLower(u.Hostname()), URL: u.String(), Now: time.Now()}
	eff, used := rules.Apply(base, f.Rules, c, f.Devices, proxy.UrlInList)
	applied := []ruleView{}
	for _, r := range f.Rules {
		for _, id := range used {
			if r.ID == id {
				applied = append(applied, ruleView{Rule: r, Summary: rules.Describe(r)})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"client_ip": clientIP,
		"url":       u.String(),
		"policy":    policyName,
		"applied":   applied,
		"effective": map[string]any{
			"adult_images": map[string]any{"enabled": eff.ImageClassifier.Enabled, "action": eff.ImageClassifier.Action},
			"adult_text":   eff.TextClassifier.Enabled,
			"ads":          eff.AdBlock.Enabled,
			"safesearch":   eff.SafeSearch.Enabled,
			"url_filter":   map[string]any{"enabled": eff.UrlFilter.Enabled, "block": eff.UrlFilter.Block, "allow": eff.UrlFilter.Allow, "categories": eff.UrlFilter.Categories},
		},
	})
}

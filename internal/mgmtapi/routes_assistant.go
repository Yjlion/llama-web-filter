package mgmtapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/policy/assistant"
	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

// registerAssistantRoutes wires the natural-language policy assistant:
//
//	GET  /api/assistant          model readiness, named devices, old rules
//	POST /api/assistant/ask      {message, history} -> reply + checked proposal
//	POST /api/assistant/apply    {proposal_id, selected} -> saves the chosen changes
//	PUT  /api/assistant/devices  {devices} -> named devices
//
// Asking never writes anything; only apply does, and it re-checks each
// change against the policies as they are at that moment.
func (s *Server) registerAssistantRoutes(r chi.Router) {
	r.Get("/api/assistant", s.handleAssistantState)
	r.Post("/api/assistant/ask", s.handleAssistantAsk)
	r.With(s.requireUnlocked).Post("/api/assistant/apply", s.handleAssistantApply)
	r.With(s.requireUnlocked).Put("/api/assistant/devices", s.handleSetDevices)
}

// proposalTTL is how long a proposal can be applied after it was made.
const proposalTTL = 15 * time.Minute

type storedProposal struct {
	changes []assistant.ChangeView
	made    time.Time
}

type proposalCache struct {
	mu sync.Mutex
	m  map[string]storedProposal
}

func (c *proposalCache) put(changes []assistant.ChangeView) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]storedProposal{}
	}
	for k, v := range c.m {
		if time.Since(v.made) > proposalTTL {
			delete(c.m, k)
		}
	}
	c.m[id] = storedProposal{changes: changes, made: time.Now()}
	return id
}

func (c *proposalCache) take(id string) ([]assistant.ChangeView, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.m[id]
	if !ok || time.Since(p.made) > proposalTTL {
		delete(c.m, id)
		return nil, false
	}
	delete(c.m, id)
	return p.changes, true
}

func (s *Server) llmClient() *client.Client {
	if s.LLMClient == nil {
		return nil
	}
	return s.LLMClient()
}

func (s *Server) assistant() (*assistant.Assistant, error) {
	f, err := s.Rules.Load()
	if err != nil {
		return nil, err
	}
	return &assistant.Assistant{Client: s.llmClient, Policies: s.Policies, Devices: f.Devices}, nil
}

func (s *Server) handleAssistantState(w http.ResponseWriter, r *http.Request) {
	f, err := s.Rules.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"llm_ready":    s.llmClient() != nil,
		"devices":      f.Devices,
		"legacy_rules": viewsOf(f.Rules),
		"categories":   sitecat.All(),
	})
}

func (s *Server) handleAssistantAsk(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Message string           `json:"message"`
		History []assistant.Turn `json:"history"`
	}
	if err := readJSON(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	a, err := s.assistant()
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
	p, err := a.Ask(ctx, payload.History, payload.Message)
	if errors.Is(err, assistant.ErrNoModel) {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	out := map[string]any{"reply": p.Reply, "changes": p.Changes, "diff": p.Diff}
	if len(p.Changes) > 0 {
		out["proposal_id"] = s.proposals.put(p.Changes)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAssistantApply(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ProposalID string `json:"proposal_id"`
		Selected   []int  `json:"selected"`
	}
	if err := readJSON(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	views, ok := s.proposals.take(payload.ProposalID)
	if !ok {
		writeJSONError(w, http.StatusGone, "This proposal has expired or was already applied; ask again.")
		return
	}
	var changes []assistant.Change
	for _, i := range payload.Selected {
		if i >= 0 && i < len(views) && views[i].Error == "" {
			changes = append(changes, views[i].Change)
		}
	}
	if len(changes) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no applicable changes selected")
		return
	}
	a, err := s.assistant()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	res, err := a.Apply(changes)
	ip := adminClientIP(r)
	now := time.Now().Unix()
	for _, n := range res.Created {
		_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{TS: now, Action: "created", PolicyName: n, ClientIP: ip})
	}
	for _, n := range res.Updated {
		_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{TS: now, Action: "updated", PolicyName: n, ClientIP: ip})
	}
	for _, n := range res.Deleted {
		_ = s.Logs.LogPolicyChange(logstore.PolicyChangeEntry{TS: now, Action: "deleted", PolicyName: n, ClientIP: ip})
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "saving failed part-way: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
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

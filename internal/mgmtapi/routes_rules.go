package mgmtapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

// registerRulesRoutes wires what remains of the sentence-rules API. New
// changes go through the assistant (routes_assistant.go), which edits the
// policies themselves; rules saved by earlier versions keep being enforced
// until they are converted or removed, so they can still be listed,
// switched off and deleted:
//
//	GET    /api/rules              the rules document (+ a summary per rule)
//	DELETE /api/rules/{id}
//	POST   /api/rules/{id}/enable  {enabled}
func (s *Server) registerRulesRoutes(r chi.Router) {
	r.Get("/api/rules", s.handleGetRules)
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
	writeJSON(w, http.StatusOK, map[string]any{"devices": f.Devices, "rules": viewsOf(f.Rules)})
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

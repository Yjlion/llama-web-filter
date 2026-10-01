package mgmtapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// DecisionStore is the verdict cache as the Decisions page sees it. Set by
// `run`; nil under standalone `mgmt`.
type DecisionStore interface {
	List(kind, query string, limit int) (any, error)
	Override(kind, key string, adult bool, note string) error
	Delete(kind, key string) error
	Clear(kind string, includeManual bool) error
	Stats() any
}

func (s *Server) registerDecisionRoutes(r chi.Router) {
	r.Get("/api/decisions", s.handleListDecisions)
	r.Get("/api/decisions/stats", s.handleDecisionStats)
	r.With(s.requireUnlocked).Post("/api/decisions/override", s.handleOverrideDecision)
	r.With(s.requireUnlocked).Delete("/api/decisions/{kind}/{key}", s.handleDeleteDecision)
	r.With(s.requireUnlocked).Post("/api/decisions/clear", s.handleClearDecisions)
}

func (s *Server) decisionsOr503(w http.ResponseWriter) (DecisionStore, bool) {
	if s.Decisions == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "The decision cache is not available in this process (run `webfilter run`).")
		return nil, false
	}
	return s.Decisions, true
}

func (s *Server) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	d, ok := s.decisionsOr503(w)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := d.List(strings.TrimSpace(r.URL.Query().Get("kind")), r.URL.Query().Get("q"), limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleDecisionStats(w http.ResponseWriter, r *http.Request) {
	d, ok := s.decisionsOr503(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, d.Stats())
}

func (s *Server) handleOverrideDecision(w http.ResponseWriter, r *http.Request) {
	d, ok := s.decisionsOr503(w)
	if !ok {
		return
	}
	var payload struct {
		Kind  string `json:"kind"`
		Key   string `json:"key"`
		Adult bool   `json:"adult"`
		Note  string `json:"note"`
	}
	if err := readJSON(r, &payload); err != nil || payload.Kind == "" || payload.Key == "" {
		writeJSONError(w, http.StatusBadRequest, "kind and key are required")
		return
	}
	if err := d.Override(payload.Kind, strings.TrimSpace(payload.Key), payload.Adult, payload.Note); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleDeleteDecision(w http.ResponseWriter, r *http.Request) {
	d, ok := s.decisionsOr503(w)
	if !ok {
		return
	}
	if err := d.Delete(chi.URLParam(r, "kind"), chi.URLParam(r, "key")); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (s *Server) handleClearDecisions(w http.ResponseWriter, r *http.Request) {
	d, ok := s.decisionsOr503(w)
	if !ok {
		return
	}
	var payload struct {
		Kind          string `json:"kind"`
		IncludeManual bool   `json:"include_manual"`
	}
	_ = readJSON(r, &payload)
	if err := d.Clear(payload.Kind, payload.IncludeManual); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared"})
}

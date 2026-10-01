package mgmtapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// AdBlockController exposes the proxy's filter-list state to the
// management API. Set by `run`; nil under standalone `mgmt`.
type AdBlockController interface {
	Status() any
	Update(ctx context.Context) (any, error)
}

func (s *Server) registerAdBlockRoutes(r chi.Router) {
	r.Get("/api/adblock/status", s.handleAdBlockStatus)
	r.With(s.requireUnlocked).Post("/api/adblock/update", s.handleAdBlockUpdate)
}

func (s *Server) handleAdBlockStatus(w http.ResponseWriter, r *http.Request) {
	if s.AdBlock == nil {
		writeJSON(w, http.StatusOK, map[string]any{"managed": false, "detail": "filter lists are loaded by the proxy process (webfilter run)"})
		return
	}
	writeJSON(w, http.StatusOK, s.AdBlock.Status())
}

func (s *Server) handleAdBlockUpdate(w http.ResponseWriter, r *http.Request) {
	if s.AdBlock == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "filter lists are managed by the proxy process (run `webfilter run`, or `webfilter adblock update`)")
		return
	}
	st, err := s.AdBlock.Update(context.WithoutCancel(r.Context()))
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

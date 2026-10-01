package mgmtapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) registerClassifierHealthRoute(r chi.Router) {
	r.Get("/api/tools/classifier-health", s.handleClassifierHealth)
}

// handleClassifierHealth reports the LLM classification backend's state.
// Text and image classification share one backend (the multimodal edge
// model), so both keys carry the same health; the split shape is kept for
// the Tools page, which renders them as two rows.
func (s *Server) handleClassifierHealth(w http.ResponseWriter, r *http.Request) {
	h := s.scannerHealth(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"text_classifier":  h,
		"image_classifier": h,
	})
}

func (s *Server) scannerHealth(r *http.Request) ScannerHealth {
	if s.Scanner == nil {
		return ScannerHealth{Available: false, Status: "unavailable", Detail: "no classification backend in this process (LLM runtime disabled or standalone mgmt)"}
	}
	return s.Scanner.Health(r.Context())
}

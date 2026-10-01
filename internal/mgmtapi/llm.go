package mgmtapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// LLMController is what the /api/llm/* routes drive. The process that owns
// the LLM service (`run`) sets Server.LLM; nil means the endpoints answer
// 503 with a reason, which is the standalone-`mgmt` case.
type LLMController interface {
	// Status returns the service's JSON-serialisable status payload.
	Status() any
	// Catalog lists the models the service can install.
	Catalog() any
	// Download starts fetching the runtime and the named model (empty =
	// configured model) in the background.
	Download(ctx context.Context, model string) error
	// CancelDownload aborts a running download.
	CancelDownload()
	// Restart stops and starts the managed server.
	Restart(ctx context.Context) error
	// RemoveModel deletes an installed model that is not in use.
	RemoveModel(id string) error
	// LogTail returns the last n bytes of the server log.
	LogTail(n int64) string
}

func (s *Server) registerLLMRoutes(r chi.Router) {
	r.Get("/api/llm/status", s.handleLLMStatus)
	r.Get("/api/llm/catalog", s.handleLLMCatalog)
	r.Get("/api/llm/log", s.handleLLMLog)
	// Downloads write to disk and restarts interrupt service, so they are
	// gated with the other configuration mutations.
	r.With(s.requireUnlocked).Post("/api/llm/download", s.handleLLMDownload)
	r.With(s.requireUnlocked).Post("/api/llm/download/cancel", s.handleLLMDownloadCancel)
	r.With(s.requireUnlocked).Post("/api/llm/restart", s.handleLLMRestart)
	r.With(s.requireUnlocked).Delete("/api/llm/models/{id}", s.handleLLMRemoveModel)
}

func (s *Server) llmOr503(w http.ResponseWriter) (LLMController, bool) {
	if s.LLM == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "The LLM runtime is not managed by this process (run `webfilter run`, not `webfilter mgmt`).")
		return nil, false
	}
	return s.LLM, true
}

func (s *Server) handleLLMStatus(w http.ResponseWriter, r *http.Request) {
	if s.LLM == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": s.Settings().LLM.Enabled, "phase": "unmanaged",
			"last_error": "The LLM runtime is not managed by this process.",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.LLM.Status())
}

func (s *Server) handleLLMCatalog(w http.ResponseWriter, r *http.Request) {
	c, ok := s.llmOr503(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, c.Catalog())
}

func (s *Server) handleLLMLog(w http.ResponseWriter, r *http.Request) {
	c, ok := s.llmOr503(w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(c.LogTail(64 << 10)))
}

func (s *Server) handleLLMDownload(w http.ResponseWriter, r *http.Request) {
	c, ok := s.llmOr503(w)
	if !ok {
		return
	}
	var payload struct {
		Model string `json:"model"`
	}
	_ = readJSON(r, &payload)
	// The download outlives this request: detach from r.Context().
	if err := c.Download(context.WithoutCancel(r.Context()), strings.TrimSpace(payload.Model)); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBusy) || strings.Contains(err.Error(), "already in progress") {
			status = http.StatusConflict
		}
		writeJSONError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started"})
}

var errBusy = errors.New("busy")

func (s *Server) handleLLMDownloadCancel(w http.ResponseWriter, r *http.Request) {
	c, ok := s.llmOr503(w)
	if !ok {
		return
	}
	c.CancelDownload()
	writeJSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
}

func (s *Server) handleLLMRestart(w http.ResponseWriter, r *http.Request) {
	c, ok := s.llmOr503(w)
	if !ok {
		return
	}
	if err := c.Restart(context.WithoutCancel(r.Context())); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "restarted"})
}

func (s *Server) handleLLMRemoveModel(w http.ResponseWriter, r *http.Request) {
	c, ok := s.llmOr503(w)
	if !ok {
		return
	}
	if err := c.RemoveModel(chi.URLParam(r, "id")); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "removed"})
}

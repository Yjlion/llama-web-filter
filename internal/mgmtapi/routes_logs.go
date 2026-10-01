package mgmtapi

import (
	"net/http"
	"strconv"
)

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "blocks"
	}
	if kind != "blocks" && kind != "requests" && kind != "policy_changes" {
		writeJSONError(w, http.StatusBadRequest, "kind must be \"blocks\", \"requests\", or \"policy_changes\"")
		return
	}

	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 5000 {
		limit = 5000
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kind":    kind,
		"entries": s.Logs.Tail(kind, limit),
	})
}

package mgmtapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/proxy/state"
	"github.com/yjlion/llama-web-filter/internal/sitecat"
)

// registerSiteCategoryRoutes wires the website taxonomy and a lookup that
// shows what category a site gets (and asks the model if it is new).
func (s *Server) registerSiteCategoryRoutes(r chi.Router) {
	r.Get("/api/sitecategories", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"categories": sitecat.All(), "available": s.Sites != nil})
	})
	r.Get("/api/sitecategories/lookup", s.handleSiteCategoryLookup)
}

func (s *Server) handleSiteCategoryLookup(w http.ResponseWriter, r *http.Request) {
	host := sitecat.HostOf(r.URL.Query().Get("host"))
	if host == "" || strings.ContainsAny(host, " \t") {
		writeJSONError(w, http.StatusBadRequest, "host is required")
		return
	}
	if s.Sites == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Site categories are not available in this process (run `webfilter run`).")
		return
	}
	ans := s.Sites.Categorize(r.Context(), state.CategoryLookup{Host: host, Enqueue: true, Budget: 10 * time.Second})
	out := map[string]any{"host": host, "site": sitecat.SiteKey(host), "known": ans.Known}
	switch {
	case ans.Known:
		out["category"] = ans.Category
		out["label"] = sitecat.Label(ans.Category)
		out["source"] = ans.Source
		out["confidence"] = ans.Confidence
	case ans.TimedOut:
		out["detail"] = "the model is still deciding; try again in a moment"
	default:
		out["detail"] = "the model is not running"
	}
	writeJSON(w, http.StatusOK, out)
}

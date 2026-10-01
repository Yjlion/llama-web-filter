package mgmtapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// registerCategoriesRoutes wires GET /api/categories, returning the shared
// site-category metadata from categories/index.json (name/count/updated per
// category) plus any top-level index metadata, mirroring the Python
// original's `{"categories": [...], **index_meta()}` shape. The list is
// empty until scripts/update_categories.sh populates the directory, in which
// case the policy editor renders its "no categories installed yet" hint.
func (s *Server) registerCategoriesRoutes(r chi.Router) {
	r.Get("/api/categories", func(w http.ResponseWriter, r *http.Request) {
		// Re-point at the current settings' categories_dir in case it
		// changed since startup (matches the Python route's configure()).
		s.Categories.Configure(s.Settings().CategoriesDir)

		body := map[string]any{"categories": s.Categories.List()}
		for k, v := range s.Categories.IndexMeta() {
			if k != "categories" {
				body[k] = v
			}
		}
		writeJSON(w, http.StatusOK, body)
	})
}

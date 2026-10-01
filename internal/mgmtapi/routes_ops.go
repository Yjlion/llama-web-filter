package mgmtapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/version"
)

// registerOpsRoutes wires the two endpoints monitoring systems consume:
// /health for load balancers and orchestrators, /metrics for Prometheus.
//
// Neither mutates configuration, so neither takes requireUnlocked - the MDM
// lock gates writes, and these are reads.
func (s *Server) registerOpsRoutes(r chi.Router) {
	r.Get("/health", s.handleHealth)
	r.Get("/metrics", s.handleMetrics)
}

type healthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// handleHealth is a liveness probe, not a readiness probe: it answers "this
// management server is up and serving" and nothing more.
//
// It is deliberately cheap. handleStatus already reports a richer view, but
// it runs two SQLite tail queries and a 300ms TCP dial per call (isPortOpen)
// - fine for a dashboard someone is looking at, wrong for something a load
// balancer hits every few seconds from several instances at once. Anything
// added here must stay allocation-light and must not touch the database.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{
		Status:        "ok",
		Version:       version.Version,
		UptimeSeconds: int64(time.Since(s.StartedAt).Seconds()),
	})
}

// handleMetrics renders the process-wide registry.
//
// Note these are in-process counters: under standalone `webfilter mgmt` the
// proxy engine is a different process, so the engine-side families are
// present but read zero. Scrape a process that actually serves traffic.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.Settings().MetricsEnabled {
		writeJSONError(w, http.StatusNotFound, "Metrics are disabled.")
		return
	}
	// Version 0.0.4 is the text exposition format every Prometheus release
	// still accepts; naming it explicitly keeps content negotiation from
	// depending on the scraper's default.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_ = metrics.Default.WriteText(w)
}

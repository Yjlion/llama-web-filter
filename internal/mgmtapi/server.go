// Package mgmtapi implements the management HTTP server: the REST API
// under /api/* plus the embedded Tailwind/Alpine web UI, matching the
// Python original's FastAPI app's endpoint paths and JSON shapes exactly
// so the UI files can be reused unmodified.
package mgmtapi

import (
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yjlion/llama-web-filter/internal/categories"
	"github.com/yjlion/llama-web-filter/internal/certs"
	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// Server holds everything the API routes need. Settings are cached
// in-memory (settingsMu-guarded) and refreshed on every read/write through
// this Server so the management API and the file on disk never drift
// within a single process - structural settings (paths, ports) still need
// a process restart to take effect, matching the Python original (its own
// backup-restore endpoint returns the same "restart to take full effect"
// note).
type Server struct {
	SettingsPath string
	Policies     *config.PolicyStore
	Logs         *logstore.Store
	CA           *certs.CA
	Categories   *categories.Store
	StartedAt    time.Time

	// OnCARotated is invoked after a successful CA import so the proxy
	// engine (Phase 4/5, when co-located in the same process via `run`)
	// can evict its leaf-certificate cache. nil (the default, e.g. under
	// standalone `mgmt`) is a valid no-op.
	OnCARotated func()

	// OnSettingsSaved is invoked after settings are persisted, so a
	// co-located proxy engine (`run`, `tray`, `gui`) applies the hot fields
	// immediately instead of waiting for its settings watcher to debounce.
	// Same shape and purpose as OnCARotated; nil is a valid no-op, which is
	// the standalone-`mgmt` case - there the proxy process picks the change
	// up from its own fsnotify watch on the file.
	OnSettingsSaved func(models.GlobalSettings)

	// Scanner is the content-classification backend behind /api/tools/scan
	// and /api/tools/classifier-health. Set by `run`, which owns the LLM
	// verdict service; nil under standalone `mgmt` or when the LLM runtime
	// is disabled, and both endpoints say so.
	Scanner ContentScanner

	// ForcePlaintext makes ServeMgmt ignore mgmt_tls and serve plain HTTP.
	// Set by the Android path (mobile/): the WebView that renders this UI has
	// no trust path to a CA-minted management leaf, and neither does the PAC
	// URL the app hands out, so a managed-configuration push that enabled
	// mgmt_tls would otherwise lock an admin out of their own device UI.
	ForcePlaintext bool

	settingsMu sync.RWMutex
	settings   models.GlobalSettings

	leafMu     sync.Mutex
	leafIssuer *certs.LeafIssuer
}

// TLSLeafIssuer returns the issuer that mints management-endpoint leaves
// from the current CA, building it on first use.
//
// It is rebuilt rather than merely cleared when the CA is replaced: a
// LeafIssuer holds its CA by pointer, and POST /api/certs/import swaps
// Server.CA for a different *CA entirely, so a Clear() alone would keep
// issuing from the old one.
func (s *Server) TLSLeafIssuer() (*certs.LeafIssuer, error) {
	s.leafMu.Lock()
	defer s.leafMu.Unlock()
	if s.leafIssuer != nil {
		return s.leafIssuer, nil
	}
	li, err := certs.NewLeafIssuer(s.CA)
	if err != nil {
		return nil, err
	}
	s.leafIssuer = li
	return li, nil
}

// ResetTLSLeafIssuer drops the cached issuer so the next handshake mints
// from whatever CA is current. Called after a CA import.
func (s *Server) ResetTLSLeafIssuer() {
	s.leafMu.Lock()
	s.leafIssuer = nil
	s.leafMu.Unlock()
}

// NewServer loads settings.json once and wires up the policy store, log
// store, and CA rooted at whatever directories that settings file
// specifies.
func NewServer(settingsPath string) (*Server, error) {
	if err := config.BootstrapRuntimeFiles(settingsPath); err != nil {
		return nil, err
	}
	s, err := config.LoadSettings(settingsPath)
	if err != nil {
		return nil, err
	}
	logs, err := logstore.Configure(s.DBPath(), s.LogRetentionDays, s.LogRequests, s.LogBlocks)
	if err != nil {
		return nil, err
	}
	ca, err := certs.LoadOrCreateCA(s.CertDir)
	if err != nil {
		return nil, err
	}
	return &Server{
		SettingsPath: settingsPath,
		Policies:     config.NewPolicyStore(s.PoliciesDir),
		Logs:         logs,
		CA:           ca,
		Categories:   categories.NewStore(s.CategoriesDir),
		StartedAt:    time.Now(),
		settings:     s,
	}, nil
}

// Settings returns the current in-memory settings snapshot.
func (s *Server) Settings() models.GlobalSettings {
	s.settingsMu.RLock()
	defer s.settingsMu.RUnlock()
	return s.settings
}

// SaveSettings persists newSettings to disk and updates the in-memory
// cache atomically with respect to concurrent readers.
func (s *Server) SaveSettings(newSettings models.GlobalSettings) error {
	if err := config.SaveSettings(s.SettingsPath, newSettings); err != nil {
		return err
	}
	s.settingsMu.Lock()
	s.settings = newSettings
	s.settingsMu.Unlock()
	if s.OnSettingsSaved != nil {
		s.OnSettingsSaved(newSettings)
	}
	return nil
}

// Router assembles the full chi router: public paths, the auth middleware
// gate, every /api/* route, PAC/WPAD, and the embedded static UI.
func (s *Server) Router() *chi.Mux {
	r := chi.NewRouter()
	r.Use(s.authMiddleware)

	r.Get("/api/version", s.handleVersion)
	r.Get("/api/auth-status", s.handleAuthStatus)
	r.Post("/api/login", s.handleLogin)
	r.Post("/api/logout", s.handleLogout)

	r.Get("/api/status", s.handleStatus)

	// Configuration mutations are additionally gated by the MDM settings
	// lock (managed.json, written by the Android managed-configuration
	// path) - reads stay open so the dashboard keeps working when locked.
	// Any new mutating config route must take the same middleware;
	// TestMutatingRoutesAreLockGated enforces this.
	r.Get("/api/policies", s.handleListPolicies)
	r.With(s.requireUnlocked).Post("/api/policies", s.handleCreatePolicy)
	r.Get("/api/policies/{name}", s.handleGetPolicy)
	r.With(s.requireUnlocked).Put("/api/policies/{name}", s.handleUpdatePolicy)
	r.With(s.requireUnlocked).Delete("/api/policies/{name}", s.handleDeletePolicy)

	r.Get("/api/settings", s.handleGetSettings)
	r.With(s.requireUnlocked).Put("/api/settings", s.handleUpdateSettings)

	r.Get("/api/logs", s.handleLogs)
	r.Get("/api/analytics", s.handleAnalytics)

	r.Get("/proxy.pac", s.handlePAC)
	r.Get("/wpad.dat", s.handlePAC)
	r.Get("/wpad.da", s.handlePAC)

	r.Get("/api/wireguard", s.handleWireguardStub)
	r.Post("/api/wireguard", s.handleWireguardStub)

	s.registerOpsRoutes(r)
	s.registerCertsRoutes(r)
	s.registerCategoriesRoutes(r)
	s.registerBackupRoutes(r)
	s.registerToolsRoutes(r)
	s.registerLogsExportRoute(r)
	s.registerClassifierHealthRoute(r)
	s.registerPolicySimulatorRoute(r)

	// Unmatched paths (including unknown /api/* paths) fall through to the
	// static handler, which returns the same {"detail":"Not Found"} JSON
	// FastAPI's default 404 handler produces (verified against the live
	// Python server) whether or not the path happens to look like an API
	// route.
	r.NotFound(staticHandler().ServeHTTP)
	r.Handle("/*", staticHandler())
	return r
}

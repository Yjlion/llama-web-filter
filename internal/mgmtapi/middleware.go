package mgmtapi

import (
	"crypto/hmac"
	"net/http"
	"strings"
)

// publicPaths bypass auth entirely - exact-match only (not prefix match),
// matching the Python original's literal path-list middleware.
var publicPaths = map[string]bool{
	"/login.html":      true,
	"/api/login":       true,
	"/api/logout":      true,
	"/api/auth-status": true,
	"/api/version":     true,
	"/proxy.pac":       true,
	"/wpad.dat":        true,
	"/wpad.da":         true,
	// Liveness probes come from load balancers, orchestrators and container
	// healthchecks, none of which can log in. The response carries only a
	// status string, the version and an uptime, so there is nothing here
	// worth gating. /metrics is deliberately NOT in this list - see
	// metricsTokenValid.
	"/health": true,
	// The CA cert is the public half of the intercepting proxy's trust
	// anchor (no private key), and every client device needs it installed
	// before it can be trusted at all - gating it behind login would make
	// devices unable to get set up until someone hands them the management
	// password, which defeats the point. mitmproxy's own mitm.it page works
	// the same way.
	"/api/ca-cert": true,
}

// isStaticAsset lets the CSS/JS/theme files the login page itself needs
// (tailwind.css, theme.css, chrome.js, i18n.js) load without auth - the
// login page couldn't render otherwise. The Python original serves these
// through the same StaticFiles mount as everything else, which is
// only reachable pre-auth for the exact-listed public paths; login.html
// itself pulls in these assets via plain relative <link>/<script> tags, so
// they must also be reachable pre-auth. This is a deliberate, minimal
// widening of the original's allowlist grounded in what login.html
// actually needs to render, not a general static-bypass.
func isStaticAsset(path string) bool {
	return strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js")
}

// metricsTokenValid reports whether r carries the configured metrics bearer
// token. A Prometheus scraper cannot complete a login form and carry a
// session cookie, but it can send a static Authorization header, so this is
// the one alternative credential the server accepts - and only for
// /metrics, which is read-only and aggregate.
//
// An empty configured token disables the mechanism entirely rather than
// matching an empty header: otherwise leaving the field blank (the default)
// would publish counters to anyone.
func metricsTokenValid(configured string, r *http.Request) bool {
	if configured == "" {
		return false
	}
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, prefix) {
		return false
	}
	// Constant-time, like the session cookie check, so the token cannot be
	// recovered a byte at a time from response timing.
	return hmac.Equal([]byte(strings.TrimPrefix(got, prefix)), []byte(configured))
}

// authMiddleware gates every request except the public allowlist. Auth is
// only enforced when both auth_enabled and password_hash are set - matches
// the Python original's "only active if both" guard. Unauthenticated API
// calls get 401 JSON; unauthenticated page loads redirect to login.html.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.Settings()
		if !cfg.AuthEnabled || cfg.PasswordHash == "" {
			next.ServeHTTP(w, r)
			return
		}
		if publicPaths[r.URL.Path] || isStaticAsset(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/metrics" && metricsTokenValid(cfg.MetricsToken, r) {
			next.ServeHTTP(w, r)
			return
		}
		if s.authTokenValid(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Machine endpoints get a 401 they can act on. /metrics is not under
		// /api/, but redirecting a scraper to an HTML login page would hand
		// it a 200 full of markup, which it would happily ingest as a failed
		// parse rather than an auth error.
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" {
			writeJSONError(w, http.StatusUnauthorized, "Not authenticated")
			return
		}
		http.Redirect(w, r, "/login.html", http.StatusFound)
	})
}

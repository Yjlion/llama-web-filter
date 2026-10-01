package mgmtapi

import "net/http"

// handleWireguardStub responds 501 rather than 404 for /api/wireguard -
// WireGuard listen mode is explicitly out of scope for this port. The
// unmodified settings.html JS treats any non-ok response identically
// (falls back to {enabled: false}, no error toast shown), so this
// degrades gracefully without any UI changes.
func (s *Server) handleWireguardStub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"enabled": false,
		"error":   "WireGuard mode is not supported in this build",
	})
}

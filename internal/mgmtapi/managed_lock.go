package mgmtapi

import (
	"net/http"

	"github.com/yjlion/llama-web-filter/internal/config"
)

// managedLockedMsg matches the writeJSONError {"detail": ...} shape the UI
// already surfaces for other 4xx responses.
const managedLockedMsg = "Settings are managed by your organization and cannot be changed here."

// requireUnlocked rejects configuration mutations while the device is under
// MDM management with settings_locked set (managed.json is written by the
// Android managed-configuration path; desktop builds never create it, so
// this middleware is a no-op there).
//
// The state file is re-read per request - deliberately not cached - so a
// lock pushed by the EMM takes effect immediately without an engine
// restart, and so the gate cannot be bypassed through the very settings API
// it protects. The file is tiny and mutations are human-scale, so the read
// cost is irrelevant. A present-but-unreadable file fails closed: this gate
// exists to resist on-device tampering, and a corrupted lock file must not
// grant write access.
func (s *Server) requireUnlocked(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, err := config.LoadManagedState(s.SettingsPath)
		if err != nil || (st.Managed && st.SettingsLocked) {
			writeJSONError(w, http.StatusForbidden, managedLockedMsg)
			return
		}
		next.ServeHTTP(w, r)
	})
}

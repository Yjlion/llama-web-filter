package mgmtapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/yjlion/llama-web-filter/internal/pwhash"
	"github.com/yjlion/llama-web-filter/internal/version"
)

// sessionCookieName matches the Python original exactly - the UI itself
// never reads this cookie directly (it's httpOnly), but the name matters
// for any documentation/tooling that references it.
const sessionCookieName = "wf_session"

const sessionMaxAge = 7 * 24 * 3600 // 7 days, matches the Python original

// sessionToken derives the deterministic session cookie value:
// hex(HMAC-SHA256(secretKey, passwordHash)). This is intentionally NOT a
// random per-session nonce - every session for a given password gets the
// same token, so "logout" is purely a client-side cookie clear (matching
// the Python original: no server-side session store). Changing the
// password changes password_hash, which changes every prior token,
// invalidating all sessions automatically.
func sessionToken(secretKey, passwordHash string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(passwordHash))
	return hex.EncodeToString(mac.Sum(nil))
}

// SessionCookie returns the session cookie name and the current valid token
// value, letting a trusted same-process front-end (the native desktop GUI in
// self-host mode) authenticate its loopback HTTP client without prompting the
// local owner for their own password. The value is the same deterministic
// token handleLogin would set; it becomes invalid when the password changes,
// exactly like a browser session.
func (s *Server) SessionCookie() (name, value string) {
	cfg := s.Settings()
	return sessionCookieName, sessionToken(cfg.SecretKey, cfg.PasswordHash)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": version.Version})
}

func (s *Server) authTokenValid(r *http.Request) bool {
	cfg := s.Settings()
	if !cfg.AuthEnabled || cfg.PasswordHash == "" {
		return true
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	want := sessionToken(cfg.SecretKey, cfg.PasswordHash)
	return hmac.Equal([]byte(cookie.Value), []byte(want))
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()
	enabled := cfg.AuthEnabled && cfg.PasswordHash != ""
	writeJSON(w, http.StatusOK, map[string]bool{
		"enabled":       enabled,
		"has_password":  cfg.PasswordHash != "",
		"authenticated": s.authTokenValid(r),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cfg := s.Settings()
	if cfg.PasswordHash == "" || !cfg.AuthEnabled {
		// No password configured / auth off: login trivially succeeds,
		// matching the Python original.
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if !pwhash.Verify(body.Password, cfg.PasswordHash) {
		writeJSONError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken(cfg.SecretKey, cfg.PasswordHash),
		Path:     "/",
		HttpOnly: true,
		// Conditional, not unconditional: a Secure cookie is never sent back
		// over plain HTTP, so setting it always would make login succeed and
		// then immediately appear to fail on every non-TLS deployment. Keyed
		// on the connection rather than mgmt_tls, because the setting can
		// disagree with what is being served: it is restart-required (a
		// saved-but-not-yet-applied mgmt_tls), and ForcePlaintext overrides
		// it on Android.
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   sessionMaxAge,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

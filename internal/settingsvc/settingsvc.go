// Package settingsvc holds the settings/policy merge and validation logic
// shared by the management HTTP API (PUT /api/settings) and the gomobile
// native-UI/MDM path (mobile.UpdateSettingsJson, mobile.ApplyManagedConfigJson).
// Both front-ends must behave byte-identically - same partial-update
// semantics, same secret-field protection, same validation messages - so the
// logic lives here and the front-ends stay thin wrappers.
package settingsvc

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/pwhash"
)

// ValidationError marks a user-correctable problem with the submitted
// settings/policy (the HTTP layer maps it to 400; anything else is a 500).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// IsValidationError reports whether err is a ValidationError.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// settingsOverlay is models.GlobalSettings without its custom
// UnmarshalJSON (Go strips methods when converting to a locally-defined
// named type). Unmarshaling into an *already-populated* value of this type
// gives partial-update semantics: only fields present in the incoming JSON
// are overwritten, everything else keeps its current value - matching the
// Python original's PUT /api/settings, which accepts a partial dict rather
// than requiring the full settings object back.
type settingsOverlay models.GlobalSettings

func generateSecretKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// MergeSettings applies a partial-update JSON body over cur and validates
// the result. Secret fields (password_hash, secret_key,
// proxy_auth_password_hash) are never accepted directly - only via the
// new_password / new_proxy_auth_password hashing path.
func MergeSettings(cur models.GlobalSettings, body []byte) (models.GlobalSettings, error) {
	overlay := settingsOverlay(cur)
	if err := json.Unmarshal(body, &overlay); err != nil {
		return models.GlobalSettings{}, &ValidationError{Msg: "invalid settings body"}
	}
	merged := models.GlobalSettings(overlay)

	merged.PasswordHash = cur.PasswordHash
	merged.SecretKey = cur.SecretKey
	merged.ProxyAuthPasswordHash = cur.ProxyAuthPasswordHash

	var extra struct {
		NewPassword          string `json:"new_password"`
		NewProxyAuthPassword string `json:"new_proxy_auth_password"`
	}
	_ = json.Unmarshal(body, &extra)

	if extra.NewPassword != "" {
		h, err := pwhash.Hash(extra.NewPassword)
		if err != nil {
			return models.GlobalSettings{}, errors.New("failed to hash password")
		}
		merged.PasswordHash = h
		if merged.SecretKey == "" {
			key, err := generateSecretKey()
			if err != nil {
				return models.GlobalSettings{}, errors.New("failed to generate secret key")
			}
			merged.SecretKey = key
		}
	}
	if extra.NewProxyAuthPassword != "" {
		h, err := pwhash.Hash(extra.NewProxyAuthPassword)
		if err != nil {
			return models.GlobalSettings{}, errors.New("failed to hash proxy auth password")
		}
		merged.ProxyAuthPasswordHash = h
	}

	if merged.AuthEnabled && merged.PasswordHash == "" {
		return models.GlobalSettings{}, &ValidationError{Msg: "Set a password before enabling authentication."}
	}
	if merged.ProxyAuthEnabled && merged.ProxyAuthPasswordHash == "" {
		return models.GlobalSettings{}, &ValidationError{Msg: "Set a proxy auth password before enabling proxy authentication."}
	}
	if err := validateMgmtTLS(merged); err != nil {
		return models.GlobalSettings{}, err
	}
	return merged, nil
}

// validateMgmtTLS rejects a management-TLS configuration that would fail at
// the next start. Catching it here turns "the UI never comes back after a
// restart" into a 400 with a reason, which matters because an operator
// enabling HTTPS on the management interface is editing it *through* that
// same interface.
//
// An empty cert/key pair is valid and means "mint a leaf from the runtime
// CA"; only a half-configured or unusable pair is an error.
func validateMgmtTLS(s models.GlobalSettings) error {
	certFile := strings.TrimSpace(s.MgmtCertFile)
	keyFile := strings.TrimSpace(s.MgmtKeyFile)

	if (certFile == "") != (keyFile == "") {
		return &ValidationError{Msg: "Set both mgmt_cert_file and mgmt_key_file, or neither (to use the built-in CA)."}
	}
	if certFile == "" {
		return nil
	}
	// Load it now rather than discovering at startup that the pair is
	// mismatched, unreadable or not a certificate at all.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return &ValidationError{Msg: "Management TLS certificate could not be loaded: " + err.Error()}
	}
	return nil
}

// SettingsDTO strips the three secret fields and adds the two derived
// has_* booleans the UI's settings.html expects, matching the Python
// original's response DTO exactly.
func SettingsDTO(s models.GlobalSettings) map[string]any {
	data, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	delete(m, "password_hash")
	delete(m, "secret_key")
	delete(m, "proxy_auth_password_hash")
	m["has_password"] = s.PasswordHash != ""
	m["has_proxy_auth"] = s.ProxyAuthPasswordHash != ""
	return m
}

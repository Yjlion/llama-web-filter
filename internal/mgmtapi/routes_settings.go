package mgmtapi

import (
	"io"
	"net/http"

	"github.com/yjlion/llama-web-filter/internal/settingsvc"
)

// The partial-update merge, secret-field protection, new_password hashing,
// and validation all live in internal/settingsvc so the gomobile native-UI
// path (mobile.UpdateSettingsJson) behaves byte-identically to this handler.

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, settingsvc.SettingsDTO(s.Settings()))
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	before := s.Settings()
	merged, err := settingsvc.MergeSettings(before, body)
	if err != nil {
		if settingsvc.IsValidationError(err) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
		} else {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	if err := s.SaveSettings(merged); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Most fields now take effect immediately; the rest are bound at startup
	// (listeners, ports, directories, capture supervisors). Naming exactly
	// which ones still need a restart beats the old blanket "restart after
	// changing settings" note, which was wrong for most saves and therefore
	// ignored. Additive field, so an older UI just does not render it.
	dto := settingsvc.SettingsDTO(merged)
	dto["restart_required"] = settingsvc.RestartRequired(before, merged)
	writeJSON(w, http.StatusOK, dto)
}

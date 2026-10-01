package mgmtapi

import (
	"encoding/json"
	"net/http"
)

// writeJSON writes v as a JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError writes {"detail": msg}, matching FastAPI's
// HTTPException(status_code=..., detail=...) response shape exactly - the
// UI's error handling (policy-editor.html, settings.html, etc.) reads
// body.detail directly.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"detail": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

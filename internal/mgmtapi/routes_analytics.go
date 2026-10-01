package mgmtapi

import (
	"net/http"
	"strconv"
	"time"
)

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			hours = n
		}
	}
	if hours < 1 {
		hours = 1
	}
	if hours > 720 {
		hours = 720
	}

	cutoff := time.Now().Unix() - int64(hours)*3600
	writeJSON(w, http.StatusOK, s.Logs.Analytics(cutoff, hours))
}

package mgmtapi

import (
	"net"
	"net/http"
	"strconv"
	"time"
)

type statusResponse struct {
	ProxyRunning   bool             `json:"proxy_running"`
	ProxyPort      int              `json:"proxy_port"`
	ProxyListen    []string         `json:"proxy_listen"`
	MgmtPort       int              `json:"mgmt_port"`
	RecentBlocks   []map[string]any `json:"recent_blocks"`
	RecentRequests []map[string]any `json:"recent_requests"`
}

const recentActivityLimit = 50

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()
	port := cfg.PrimaryProxyPort()

	writeJSON(w, http.StatusOK, statusResponse{
		ProxyRunning:   isPortOpen(port),
		ProxyPort:      port,
		ProxyListen:    cfg.ProxyListen,
		MgmtPort:       cfg.MgmtPort,
		RecentBlocks:   s.Logs.Tail("blocks", recentActivityLimit),
		RecentRequests: s.Logs.Tail("requests", recentActivityLimit),
	})
}

// isPortOpen checks whether something is already listening on 127.0.0.1 (or
// ::1) at port - the proxy_running signal, matching the Python original's
// approach of probing the port rather than tracking a PID (works whether
// the proxy runs in this same process via `run` or as a separate `proxy`
// process).
func isPortOpen(port int) bool {
	portStr := strconv.Itoa(port)
	for _, host := range []string{"127.0.0.1", "::1"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portStr), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

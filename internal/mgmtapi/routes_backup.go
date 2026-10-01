package mgmtapi

import "github.com/go-chi/chi/v5"

// registerBackupRoutes wires GET/POST /api/backup once the atomic
// export/import bundle logic (Phase 9 of the project plan) lands.
// NOTE: when it does, the restore/import route must be wrapped with
// s.requireUnlocked (MDM settings lock) like every other config mutation -
// TestMutatingRoutesAreLockGated will fail until it is.
func (s *Server) registerBackupRoutes(r chi.Router) {}

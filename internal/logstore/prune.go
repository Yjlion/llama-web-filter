package logstore

import (
	"fmt"
	"time"
)

// Prune deletes rows older than retentionDays. A retentionDays of 0 (or
// less) means "keep everything" and is a no-op, matching the Python
// original. Called on Configure() and automatically every 500 inserts.
func (s *Store) Prune() error {
	if s.retentionDays <= 0 {
		return nil
	}
	cutoff := time.Now().Unix() - int64(s.retentionDays)*86400

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.writeDB.Exec("DELETE FROM requests WHERE ts < ?", cutoff); err != nil {
		return fmt.Errorf("prune requests: %w", err)
	}
	if _, err := s.writeDB.Exec("DELETE FROM blocks WHERE ts < ?", cutoff); err != nil {
		return fmt.Errorf("prune blocks: %w", err)
	}
	return nil
}

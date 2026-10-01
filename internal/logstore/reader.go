package logstore

import (
	"database/sql"
	"fmt"
)

// Reader is a write-free view over an existing webfilter.db: it opens
// fresh read-only connections per call (the same read path Store uses,
// safe alongside the engine's WAL writer) and never creates, migrates, or
// prunes the database. It is the way out-of-process-style consumers — the
// gomobile logs/analytics exports — read logs without contending for the
// single-writer connection; do NOT Configure() a second Store for that.
//
// A missing or unreadable database yields empty results, matching the
// established fail-open read convention.
type Reader struct {
	dbPath string
}

// NewReader returns a read-only view over the database at dbPath. The file
// does not need to exist.
func NewReader(dbPath string) *Reader {
	return &Reader{dbPath: dbPath}
}

// openReadConn opens a fresh read-only connection, matching the Python
// original's "open a new ro connection per call" read path.
func (r *Reader) openReadConn() (*sql.DB, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", r.dbPath))
	if err != nil {
		return nil, fmt.Errorf("open read-only db: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

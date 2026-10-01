// Package logstore is the SQLite-backed request/block log, shared by the
// proxy engine (sole writer) and the management API (read-only queries),
// via one WAL-mode database file - mirrors shared/logstore.py exactly,
// including its schema, single-writer-plus-mutex pattern, and periodic
// pruning.
package logstore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers "sqlite"
)

const pruneEvery = 500

const schemaSQL = `
CREATE TABLE IF NOT EXISTS requests (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  method     TEXT,
  host       TEXT,
  path       TEXT,
  status     INTEGER,
  action     TEXT,
  component  TEXT,
  policy     TEXT,
  client_ip  TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);

CREATE TABLE IF NOT EXISTS blocks (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,
  domain    TEXT,
  url       TEXT,
  reason    TEXT,
  component TEXT,
  policy    TEXT,
  client_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(ts);

CREATE TABLE IF NOT EXISTS policy_changes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  action      TEXT,
  policy_name TEXT,
  old_name    TEXT,
  client_ip   TEXT
);
CREATE INDEX IF NOT EXISTS idx_policy_changes_ts ON policy_changes(ts);
`

// RequestColumns, BlockColumns, and PolicyChangeColumns list each table's
// columns in insertion/export order (excluding the internal "id" primary
// key). RequestColumns/BlockColumns mirror the Python original's
// REQUEST_COLUMNS/BLOCK_COLUMNS tuples exactly - used for both INSERT
// statements and CSV/XLSX export headers.
var (
	RequestColumns      = []string{"ts", "method", "host", "path", "status", "action", "component", "policy", "client_ip", "user_agent"}
	BlockColumns        = []string{"ts", "domain", "url", "reason", "component", "policy", "client_ip"}
	PolicyChangeColumns = []string{"ts", "action", "policy_name", "old_name", "client_ip"}
)

// Store is a configured logstore instance: one persistent write connection
// (guarded by a mutex, matching the Python original's single-writer
// design) plus fresh read-only connections opened per read call so
// concurrent reads from the management API never block the writer. The
// read path (Tail/RowsInRange/Analytics) is the embedded Reader.
type Store struct {
	Reader
	retentionDays int
	logRequests   bool
	logBlocks     bool

	writeDB     *sql.DB
	writeMu     sync.Mutex
	insertCount atomic.Int64
}

// Configure opens (creating if needed) the SQLite database at dbPath,
// applies the schema, and returns a ready-to-use Store. Idempotent - safe
// to call multiple times against the same path.
func Configure(dbPath string, retentionDays int, logRequests, logBlocks bool) (*Store, error) {
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create logs dir: %w", err)
		}
	}

	writeDB, err := openWriteConn(dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := writeDB.Exec(schemaSQL); err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	s := &Store{
		Reader:        Reader{dbPath: dbPath},
		retentionDays: retentionDays,
		logRequests:   logRequests,
		logBlocks:     logBlocks,
		writeDB:       writeDB,
	}
	s.Prune()
	return s, nil
}

func openWriteConn(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // single writer, matches the Python original's threading.Lock-guarded single connection
	if err := applyWritePragmas(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func applyWritePragmas(db *sql.DB) error {
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("%s: %w", pragma, err)
		}
	}
	return nil
}

// Close closes the write connection.
func (s *Store) Close() error {
	return s.writeDB.Close()
}

// Package verdict is the decision layer between the proxy's classifier
// addons and the edge LLM: a persistent cache of verdicts keyed by content,
// a deduplicating job queue in front of the model, per-request wait
// budgets, and site-level learning. The pipeline never calls the model
// directly; it asks this package, which answers from cache in microseconds
// or waits on the model for at most the caller's budget.
package verdict

import (
	"container/list"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Kind is the content type a verdict is about.
type Kind string

const (
	KindImage Kind = "image"
	KindText  Kind = "text"
	KindHost  Kind = "host"
	KindSite  Kind = "site" // eTLD+1 level verdict learned from pages/images
	// KindCategory is a website's taxonomy category (internal/sitecat),
	// keyed by eTLD+1, or by exact host for a manual override.
	KindCategory Kind = "category"
)

// Source says where a verdict came from, in increasing order of authority.
type Source string

const (
	SourcePrefilter Source = "prefilter" // size/type rule, never the model
	SourceLLM       Source = "llm"
	SourceLearned   Source = "learned" // site-level aggregation
	SourceManual    Source = "manual"  // operator override; wins over all
	// SourceList marks a category answered by an installed domain list. It
	// is never stored: the lists are consulted on every lookup.
	SourceList Source = "list"
)

// Decision is one cached verdict.
type Decision struct {
	Kind       Kind      `json:"kind"`
	Key        string    `json:"key"`
	Score      float64   `json:"score"`
	Adult      bool      `json:"adult"`
	Source     Source    `json:"source"`
	Model      string    `json:"model,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	Hint       string    `json:"hint,omitempty"` // URL or host the content was seen at
	Created    time.Time `json:"created"`
	Hits       int64     `json:"hits"`
	Confidence float64   `json:"confidence"`
	// Category is the taxonomy slug for KindCategory rows.
	Category string `json:"category,omitempty"`
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS decisions (
  kind       TEXT NOT NULL,
  key        TEXT NOT NULL,
  score      REAL NOT NULL,
  adult      INTEGER NOT NULL,
  source     TEXT NOT NULL,
  model      TEXT,
  detail     TEXT,
  hint       TEXT,
  confidence REAL NOT NULL DEFAULT 0,
  created    INTEGER NOT NULL,
  hits       INTEGER NOT NULL DEFAULT 0,
  category   TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS idx_decisions_created ON decisions(created);
CREATE TABLE IF NOT EXISTS sites (
  site       TEXT PRIMARY KEY,
  adult_hits INTEGER NOT NULL DEFAULT 0,
  total      INTEGER NOT NULL DEFAULT 0,
  updated    INTEGER NOT NULL
);
`

// Store is the SQLite-backed decision cache with an in-memory LRU front.
type Store struct {
	db  *sql.DB
	mu  sync.Mutex
	lru *lruCache
	// pending hits are flushed in batches so a cache hit costs no disk I/O.
	hitMu sync.Mutex
	hits  map[string]int64
}

// Open opens or creates the decision database at path.
func Open(path string, lruSize int) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("decision schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("decision schema migration: %w", err)
	}
	if lruSize <= 0 {
		lruSize = 50000
	}
	return &Store{db: db, lru: newLRU(lruSize), hits: map[string]int64{}}, nil
}

// migrate brings a database created by an older version up to schemaSQL.
func migrate(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(decisions)`)
	if err != nil {
		return err
	}
	has := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		has[name] = true
	}
	rows.Close()
	if !has["category"] {
		if _, err := db.Exec(`ALTER TABLE decisions ADD COLUMN category TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// OpenMemory opens an in-memory store (tests, or when no data dir).
func OpenMemory() (*Store, error) { return Open(":memory:", 10000) }

// Close flushes hit counts and closes the database.
func (s *Store) Close() error {
	s.flushHits()
	return s.db.Close()
}

func cacheKey(kind Kind, key string) string { return string(kind) + "\x00" + key }

// Get returns a cached decision.
func (s *Store) Get(kind Kind, key string) (Decision, bool) {
	ck := cacheKey(kind, key)
	if d, ok := s.lru.get(ck); ok {
		s.countHit(ck)
		return d, true
	}
	row := s.db.QueryRow(`SELECT score, adult, source, model, detail, hint, confidence, created, hits, category FROM decisions WHERE kind=? AND key=?`, kind, key)
	var d Decision
	var adult int
	var created int64
	var model, detail, hint sql.NullString
	if err := row.Scan(&d.Score, &adult, &d.Source, &model, &detail, &hint, &d.Confidence, &created, &d.Hits, &d.Category); err != nil {
		return Decision{}, false
	}
	d.Kind, d.Key, d.Adult = kind, key, adult != 0
	d.Model, d.Detail, d.Hint = model.String, detail.String, hint.String
	d.Created = time.Unix(created, 0)
	s.lru.put(ck, d)
	s.countHit(ck)
	return d, true
}

// Put stores a decision. A manual decision is never overwritten by a lower
// authority source.
func (s *Store) Put(d Decision) error {
	if d.Created.IsZero() {
		d.Created = time.Now()
	}
	if existing, ok := s.Get(d.Kind, d.Key); ok && existing.Source == SourceManual && d.Source != SourceManual {
		return nil
	}
	adult := 0
	if d.Adult {
		adult = 1
	}
	_, err := s.db.Exec(`INSERT INTO decisions(kind,key,score,adult,source,model,detail,hint,confidence,created,hits,category)
		VALUES(?,?,?,?,?,?,?,?,?,?,0,?)
		ON CONFLICT(kind,key) DO UPDATE SET score=excluded.score, adult=excluded.adult, source=excluded.source,
		  model=excluded.model, detail=excluded.detail, hint=excluded.hint, confidence=excluded.confidence, created=excluded.created,
		  category=excluded.category`,
		d.Kind, d.Key, d.Score, adult, d.Source, d.Model, d.Detail, d.Hint, d.Confidence, d.Created.Unix(), d.Category)
	if err != nil {
		return err
	}
	s.lru.put(cacheKey(d.Kind, d.Key), d)
	return nil
}

// Delete removes one decision.
func (s *Store) Delete(kind Kind, key string) error {
	s.lru.remove(cacheKey(kind, key))
	_, err := s.db.Exec(`DELETE FROM decisions WHERE kind=? AND key=?`, kind, key)
	return err
}

// Clear removes every decision of a kind ("" = all) except manual ones
// unless includeManual is set.
func (s *Store) Clear(kind Kind, includeManual bool) error {
	s.lru.purge()
	q := `DELETE FROM decisions WHERE 1=1`
	var args []any
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	if !includeManual {
		q += ` AND source<>?`
		args = append(args, SourceManual)
	}
	_, err := s.db.Exec(q, args...)
	return err
}

// List returns decisions newest first, optionally filtered by kind and a
// substring of the key or hint.
func (s *Store) List(kind Kind, query string, limit int) ([]Decision, error) {
	s.flushHits()
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT kind, key, score, adult, source, model, detail, hint, confidence, created, hits, category FROM decisions WHERE 1=1`
	var args []any
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	if query = strings.TrimSpace(query); query != "" {
		q += ` AND (key LIKE ? OR hint LIKE ? OR detail LIKE ? OR category LIKE ?)`
		like := "%" + query + "%"
		args = append(args, like, like, like, like)
	}
	q += ` ORDER BY created DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var d Decision
		var adult int
		var created int64
		var model, detail, hint sql.NullString
		if err := rows.Scan(&d.Kind, &d.Key, &d.Score, &adult, &d.Source, &model, &detail, &hint, &d.Confidence, &created, &d.Hits, &d.Category); err != nil {
			return nil, err
		}
		d.Adult = adult != 0
		d.Model, d.Detail, d.Hint = model.String, detail.String, hint.String
		d.Created = time.Unix(created, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Stats summarises the cache for the status page.
type Stats struct {
	Total  int64            `json:"total"`
	ByKind map[string]int64 `json:"by_kind"`
	Adult  int64            `json:"adult"`
	Manual int64            `json:"manual"`
	Sites  int64            `json:"sites"`
}

// Stats counts rows by kind.
func (s *Store) Stats() Stats {
	st := Stats{ByKind: map[string]int64{}}
	rows, err := s.db.Query(`SELECT kind, COUNT(*), SUM(adult), SUM(source='manual') FROM decisions GROUP BY kind`)
	if err != nil {
		return st
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n, adult, manual sql.NullInt64
		if err := rows.Scan(&kind, &n, &adult, &manual); err == nil {
			st.ByKind[kind] = n.Int64
			st.Total += n.Int64
			st.Adult += adult.Int64
			st.Manual += manual.Int64
		}
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sites`).Scan(&st.Sites)
	return st
}

func (s *Store) countHit(ck string) {
	s.hitMu.Lock()
	s.hits[ck]++
	n := len(s.hits)
	s.hitMu.Unlock()
	if n >= 256 {
		s.flushHits()
	}
}

func (s *Store) flushHits() {
	s.hitMu.Lock()
	pending := s.hits
	s.hits = map[string]int64{}
	s.hitMu.Unlock()
	if len(pending) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	for ck, n := range pending {
		kind, key, _ := strings.Cut(ck, "\x00")
		_, _ = tx.Exec(`UPDATE decisions SET hits=hits+? WHERE kind=? AND key=?`, n, kind, key)
	}
	_ = tx.Commit()
}

// ---- site-level learning ----

// SiteAdultThreshold is how many adult verdicts a site needs before it is
// treated as adult as a whole; SiteAdultRatio is the minimum share of its
// verdicts that must be adult.
const (
	SiteAdultThreshold = 3
	SiteAdultRatio     = 0.5
)

// RecordSite tallies one page/image verdict against its site and returns
// whether the site has crossed the adult threshold.
func (s *Store) RecordSite(site string, adult bool) bool {
	if site == "" {
		return false
	}
	a := 0
	if adult {
		a = 1
	}
	_, _ = s.db.Exec(`INSERT INTO sites(site, adult_hits, total, updated) VALUES(?,?,1,?)
		ON CONFLICT(site) DO UPDATE SET adult_hits=adult_hits+?, total=total+1, updated=?`,
		site, a, time.Now().Unix(), a, time.Now().Unix())
	var hits, total int64
	if err := s.db.QueryRow(`SELECT adult_hits, total FROM sites WHERE site=?`, site).Scan(&hits, &total); err != nil {
		return false
	}
	learned := hits >= SiteAdultThreshold && float64(hits) >= SiteAdultRatio*float64(total)
	if learned {
		if _, ok := s.Get(KindSite, site); !ok {
			_ = s.Put(Decision{Kind: KindSite, Key: site, Score: 0.95, Adult: true, Source: SourceLearned, Detail: fmt.Sprintf("%d of %d verdicts adult", hits, total), Confidence: float64(hits) / float64(total)})
		}
	}
	return learned
}

// SiteAdult reports whether a site has a stored adult verdict.
func (s *Store) SiteAdult(site string) (Decision, bool) {
	d, ok := s.Get(KindSite, site)
	return d, ok && d.Adult
}

// ---- LRU ----

type lruCache struct {
	mu    sync.Mutex
	size  int
	ll    *list.List
	items map[string]*list.Element
}

type lruEntry struct {
	key string
	val Decision
}

func newLRU(size int) *lruCache {
	return &lruCache{size: size, ll: list.New(), items: map[string]*list.Element{}}
}

func (c *lruCache) get(k string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*lruEntry).val, true
	}
	return Decision{}, false
}

func (c *lruCache) put(k string, v Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.Value.(*lruEntry).val = v
		c.ll.MoveToFront(e)
		return
	}
	c.items[k] = c.ll.PushFront(&lruEntry{key: k, val: v})
	for c.ll.Len() > c.size {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*lruEntry).key)
	}
}

func (c *lruCache) remove(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.ll.Remove(e)
		delete(c.items, k)
	}
}

func (c *lruCache) purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = map[string]*list.Element{}
}

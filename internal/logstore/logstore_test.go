package logstore_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/logstore"
)

func newTestStore(t *testing.T, retentionDays int) *logstore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webfilter.db")
	s, err := logstore.Configure(path, retentionDays, true, true)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLogRequestAndTail(t *testing.T) {
	s := newTestStore(t, 30)
	now := time.Now().Unix()

	for i := 0; i < 3; i++ {
		err := s.LogRequest(logstore.RequestEntry{
			TS: now + int64(i), Method: "GET", Host: "example.com", Path: "/", Status: 200,
			Action: "ok", ClientIP: "10.0.0.1", UserAgent: "test-agent",
		})
		if err != nil {
			t.Fatalf("LogRequest: %v", err)
		}
	}

	rows := s.Tail("requests", 10)
	if len(rows) != 3 {
		t.Fatalf("Tail returned %d rows, want 3", len(rows))
	}
	// Newest first.
	if rows[0]["ts"] != now+2 {
		t.Errorf("rows[0][ts] = %v, want %d (newest first)", rows[0]["ts"], now+2)
	}
	if _, hasID := rows[0]["id"]; hasID {
		t.Errorf("row should not include the internal id column")
	}
	if rows[0]["user_agent"] != "test-agent" {
		t.Errorf("user_agent = %v, want test-agent", rows[0]["user_agent"])
	}
}

func TestTailLimit(t *testing.T) {
	s := newTestStore(t, 30)
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		_ = s.LogRequest(logstore.RequestEntry{TS: now + int64(i), Action: "ok"})
	}
	if got := s.Tail("requests", 2); len(got) != 2 {
		t.Errorf("Tail(limit=2) returned %d rows, want 2", len(got))
	}
}

func TestLogBlockAndAnalytics(t *testing.T) {
	s := newTestStore(t, 30)
	now := time.Now().Unix()

	_ = s.LogBlock(logstore.BlockEntry{TS: now, Domain: "evil.com", Component: "url_filter", Policy: "kids", ClientIP: "10.0.0.5"})
	_ = s.LogBlock(logstore.BlockEntry{TS: now, Domain: "evil.com", Component: "url_filter", Policy: "kids", ClientIP: "10.0.0.5"})
	_ = s.LogBlock(logstore.BlockEntry{TS: now, Domain: "bad.com", Component: "doh_filter", Policy: "kids", ClientIP: "10.0.0.5"})
	_ = s.LogRequest(logstore.RequestEntry{TS: now, Action: "blocked", ClientIP: "10.0.0.5", Policy: "kids"})
	_ = s.LogRequest(logstore.RequestEntry{TS: now, Action: "ok", ClientIP: "10.0.0.5", Policy: "kids"})

	a := s.Analytics(now-3600, 24)
	if a.TotalBlocks != 3 {
		t.Errorf("TotalBlocks = %d, want 3", a.TotalBlocks)
	}
	if a.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", a.TotalRequests)
	}
	if len(a.TopBlockedDomains) != 2 || a.TopBlockedDomains[0].Domain != "evil.com" || a.TopBlockedDomains[0].Count != 2 {
		t.Errorf("TopBlockedDomains = %+v, want [{evil.com 2} {bad.com 1}]", a.TopBlockedDomains)
	}
	if len(a.PerDevice) != 1 || a.PerDevice[0].Total != 2 || a.PerDevice[0].Blocked != 1 {
		t.Errorf("PerDevice = %+v, want one device with total=2 blocked=1", a.PerDevice)
	}
}

func TestPruneRemovesOldRows(t *testing.T) {
	s := newTestStore(t, 1) // 1-day retention
	old := time.Now().Add(-48 * time.Hour).Unix()
	recent := time.Now().Unix()

	_ = s.LogRequest(logstore.RequestEntry{TS: old, Action: "ok"})
	_ = s.LogRequest(logstore.RequestEntry{TS: recent, Action: "ok"})

	if err := s.Prune(); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	rows := s.Tail("requests", 100)
	if len(rows) != 1 {
		t.Fatalf("after prune, got %d rows, want 1", len(rows))
	}
	if rows[0]["ts"] != recent {
		t.Errorf("surviving row ts = %v, want %d (the recent one)", rows[0]["ts"], recent)
	}
}

func TestPruneDisabledWhenRetentionZero(t *testing.T) {
	s := newTestStore(t, 0)
	old := time.Now().Add(-365 * 24 * time.Hour).Unix()
	_ = s.LogRequest(logstore.RequestEntry{TS: old, Action: "ok"})
	if err := s.Prune(); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if rows := s.Tail("requests", 100); len(rows) != 1 {
		t.Errorf("retention_days=0 should keep everything, got %d rows", len(rows))
	}
}

func TestRowsInRange(t *testing.T) {
	s := newTestStore(t, 30)
	base := time.Now().Unix()
	for i := int64(0); i < 5; i++ {
		_ = s.LogBlock(logstore.BlockEntry{TS: base + i*100, Domain: "d.com"})
	}
	rows := s.RowsInRange("blocks", base+100, base+300)
	if len(rows) != 3 {
		t.Fatalf("RowsInRange returned %d rows, want 3", len(rows))
	}
	if rows[0]["ts"] != base+100 {
		t.Errorf("rows[0][ts] = %v, want ascending order starting at %d", rows[0]["ts"], base+100)
	}
}

func TestInvalidKindReturnsEmpty(t *testing.T) {
	s := newTestStore(t, 30)
	if rows := s.Tail("dropTableRequests", 10); len(rows) != 0 {
		t.Errorf("Tail with invalid kind returned %d rows, want 0", len(rows))
	}
}

func TestLogDisabledIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webfilter.db")
	s, err := logstore.Configure(path, 30, false, false)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	defer s.Close()

	_ = s.LogRequest(logstore.RequestEntry{TS: time.Now().Unix(), Action: "ok"})
	_ = s.LogBlock(logstore.BlockEntry{TS: time.Now().Unix(), Domain: "x.com"})

	if rows := s.Tail("requests", 10); len(rows) != 0 {
		t.Errorf("log_requests=false should be a no-op, got %d rows", len(rows))
	}
	if rows := s.Tail("blocks", 10); len(rows) != 0 {
		t.Errorf("log_blocks=false should be a no-op, got %d rows", len(rows))
	}
}

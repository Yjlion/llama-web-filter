package logstore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReaderOnMissingDatabaseIsEmpty(t *testing.T) {
	r := NewReader(filepath.Join(t.TempDir(), "nope", "webfilter.db"))
	if got := r.Tail("blocks", 10); len(got) != 0 {
		t.Errorf("Tail on missing DB = %v, want empty", got)
	}
	a := r.Analytics(0, 24)
	if a.TotalRequests != 0 || a.TotalBlocks != 0 || a.WindowHours != 24 {
		t.Errorf("Analytics on missing DB = %+v, want zeroed with window echoed", a)
	}
	if a.RequestActions == nil || a.TopBlockedDomains == nil {
		t.Error("Analytics on missing DB must keep non-nil (JSON-friendly) fields")
	}
}

// TestReaderSeesStoreWritesWhileStoreIsOpen pins the concurrency contract
// the mobile exports rely on: a Reader's fresh ro connections read rows
// while the engine's Store still holds the WAL write connection.
func TestReaderSeesStoreWritesWhileStoreIsOpen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "webfilter.db")
	s, err := Configure(dbPath, 30, true, true)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	defer s.Close()

	now := time.Now().Unix()
	if err := s.LogRequest(RequestEntry{TS: now, Method: "GET", Host: "a.example", Action: "blocked", Policy: "default"}); err != nil {
		t.Fatalf("LogRequest: %v", err)
	}
	if err := s.LogBlock(BlockEntry{TS: now, Domain: "a.example", Reason: "category", Component: "url_filter"}); err != nil {
		t.Fatalf("LogBlock: %v", err)
	}

	r := NewReader(dbPath) // Store still open — no writer contention allowed
	rows := r.Tail("blocks", 10)
	if len(rows) != 1 || rows[0]["domain"] != "a.example" {
		t.Fatalf("Reader.Tail = %v, want the seeded block", rows)
	}

	// Parity with the Store's own read path.
	storeAnalytics := s.Analytics(now-10, 1)
	readerAnalytics := r.Analytics(now-10, 1)
	if storeAnalytics.TotalRequests != readerAnalytics.TotalRequests ||
		storeAnalytics.TotalBlocks != readerAnalytics.TotalBlocks {
		t.Errorf("Store/Reader analytics diverge: %+v vs %+v", storeAnalytics, readerAnalytics)
	}
	if readerAnalytics.TotalBlocks != 1 || readerAnalytics.RequestActions["blocked"] != 1 {
		t.Errorf("Reader analytics = %+v, want the seeded activity", readerAnalytics)
	}
}

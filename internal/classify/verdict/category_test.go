package verdict

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestCategoryListsThenCacheThenModel(t *testing.T) {
	b := &fakeBackend{}
	b.ready.Store(true)
	s := newTestService(t, b)
	ctx := context.Background()

	// Lists answer first, without the model.
	a := s.Category(ctx, CategoryRequest{Host: "www.shop.example", ListCategory: "gambling", Enqueue: true, Budget: time.Second})
	if !a.Known || a.Category != "gambling" || a.Source != SourceList || b.calls.Load() != 0 {
		t.Fatalf("list answer = %+v, calls %d", a, b.calls.Load())
	}

	// Cache-only lookup of an unknown site neither waits nor asks.
	a = s.Category(ctx, CategoryRequest{Host: "www.store.example"})
	if a.Known || a.TimedOut || a.Unavailable || b.calls.Load() != 0 {
		t.Fatalf("cache-only = %+v", a)
	}

	// The model answers within the budget and is cached per site.
	a = s.Category(ctx, CategoryRequest{Host: "www.store.example", Enqueue: true, Budget: time.Second})
	if !a.Known || a.Category != "shopping" || a.Source != SourceLLM {
		t.Fatalf("model answer = %+v", a)
	}
	a = s.Category(ctx, CategoryRequest{Host: "m.store.example"})
	if !a.Known || !a.Cached || a.Category != "shopping" || b.calls.Load() != 1 {
		t.Fatalf("site cache = %+v calls %d", a, b.calls.Load())
	}

	// A low-confidence hostname verdict is refined once the title is known.
	_ = s.Category(ctx, CategoryRequest{Host: "www.store.example", Title: "Daily News", Enqueue: true})
	deadline := time.Now().Add(2 * time.Second)
	for {
		d, _ := s.Store().Get(KindCategory, "store.example")
		if d.Category == "news" && d.Detail == categoryFromPage {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not refined: %+v", d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCategoryManualOverrideWins(t *testing.T) {
	b := &fakeBackend{}
	b.ready.Store(true)
	s := newTestService(t, b)
	if err := s.OverrideCategory("bank.example", "banking_finance", "mine"); err != nil {
		t.Fatal(err)
	}
	if err := s.OverrideCategory("x.example", "nope", ""); err == nil {
		t.Fatal("unknown slug accepted")
	}
	a := s.Category(context.Background(), CategoryRequest{Host: "www.bank.example", ListCategory: "phishing", Enqueue: true})
	if a.Category != "banking_finance" || a.Source != SourceManual {
		t.Fatalf("override = %+v", a)
	}
	// An exact-host override beats the site's.
	_ = s.OverrideCategory("games.bank.example", "gaming", "")
	a = s.Category(context.Background(), CategoryRequest{Host: "games.bank.example"})
	if a.Category != "gaming" {
		t.Fatalf("host override = %+v", a)
	}
}

func TestCategoryUnavailable(t *testing.T) {
	s := newTestService(t, &fakeBackend{})
	a := s.Category(context.Background(), CategoryRequest{Host: "a.example", Enqueue: true, Budget: time.Second})
	if !a.Unavailable {
		t.Fatalf("got %+v", a)
	}
}

func TestStoreMigratesOldSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE decisions (kind TEXT NOT NULL, key TEXT NOT NULL, score REAL NOT NULL, adult INTEGER NOT NULL,
		source TEXT NOT NULL, model TEXT, detail TEXT, hint TEXT, confidence REAL NOT NULL DEFAULT 0, created INTEGER NOT NULL,
		hits INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (kind, key));
		INSERT INTO decisions VALUES('host','ads.example',0.9,1,'llm','m','ads','',0.9,1,0);`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	st, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if d, ok := st.Get(KindHost, "ads.example"); !ok || !d.Adult {
		t.Fatalf("old row lost: %+v %v", d, ok)
	}
	if err := st.Put(Decision{Kind: KindCategory, Key: "news.example", Category: "news", Source: SourceLLM}); err != nil {
		t.Fatal(err)
	}
	st.lru.purge()
	if d, _ := st.Get(KindCategory, "news.example"); d.Category != "news" {
		t.Fatalf("category not persisted: %+v", d)
	}
}

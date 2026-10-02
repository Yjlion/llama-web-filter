package verdict

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/disintegration/imaging"
)

type fakeBackend struct {
	ready    atomic.Bool
	vision   bool
	delay    time.Duration
	calls    atomic.Int64
	imgScore float64
	txtAdult bool
	mu       sync.Mutex
	hosts    map[string]bool
}

func (f *fakeBackend) Ready() bool     { return f.ready.Load() }
func (f *fakeBackend) ModelID() string { return "fake" }
func (f *fakeBackend) Vision() bool    { return f.vision }
func (f *fakeBackend) Image(ctx context.Context, mime string, data []byte, hint string) (Result, error) {
	f.calls.Add(1)
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	return Result{Score: f.imgScore, Adult: f.imgScore >= 0.5, Confidence: 0.9, Detail: "fake image"}, nil
}
func (f *fakeBackend) Text(ctx context.Context, url, title, text string) (Result, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	if f.txtAdult {
		return Result{Score: 0.95, Adult: true, Confidence: 0.9, Detail: "fake adult"}, nil
	}
	return Result{Score: 0.05, Adult: false, Confidence: 0.9, Detail: "fake clean"}, nil
}
func (f *fakeBackend) Host(ctx context.Context, host string, paths []string) (Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hosts[host] {
		return Result{Score: 0.9, Adult: true, Confidence: 0.9, Detail: "ads"}, nil
	}
	return Result{Score: 0.1, Adult: false, Confidence: 0.9, Detail: "content"}, nil
}

func (f *fakeBackend) Site(ctx context.Context, host, title, desc string) (Result, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	if title != "" {
		return Result{Category: "news", Confidence: 0.9}, nil
	}
	return Result{Category: "shopping", Confidence: 0.5}, nil
}

func newTestService(t *testing.T, b *fakeBackend) *Service {
	t.Helper()
	st, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, b, Options{Workers: 2, QueueLimit: 8, MaxImagePx: 128})
	t.Cleanup(s.Close)
	return s
}

func testPNG(t *testing.T, w, h int, seed uint8) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x) + seed, uint8(y), uint8(x*y) ^ seed, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestImageVerdictCachesAndCoalesces(t *testing.T) {
	b := &fakeBackend{vision: true, delay: 50 * time.Millisecond, imgScore: 0.9}
	b.ready.Store(true)
	s := newTestService(t, b)
	img := testPNG(t, 200, 150, 1)

	// First sighting waits on the model within budget.
	a := s.Image(context.Background(), ImageRequest{URL: "https://x.example/a.png", Data: img, Budget: 2 * time.Second})
	if !a.Known || !a.Adult || a.Source != SourceLLM || a.Cached {
		t.Fatalf("first answer = %+v", a)
	}
	// Second sighting is a cache hit with no model call.
	before := b.calls.Load()
	a = s.Image(context.Background(), ImageRequest{URL: "https://x.example/a.png", Data: img, Budget: time.Millisecond})
	if !a.Known || !a.Cached || b.calls.Load() != before {
		t.Fatalf("second answer should be cached: %+v calls=%d", a, b.calls.Load()-before)
	}

	// Concurrent requests for a new image share one job.
	img2 := testPNG(t, 200, 150, 77)
	var wg sync.WaitGroup
	before = b.calls.Load()
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Image(context.Background(), ImageRequest{URL: "https://y.example/b.png", Data: img2, Budget: 2 * time.Second})
		}()
	}
	wg.Wait()
	if got := b.calls.Load() - before; got != 1 {
		t.Fatalf("5 concurrent requests made %d model calls, want 1", got)
	}
}

func TestImageNearDuplicateSharesVerdict(t *testing.T) {
	b := &fakeBackend{vision: true, imgScore: 0.9}
	b.ready.Store(true)
	s := newTestService(t, b)
	big := testPNG(t, 300, 200, 5)
	s.Image(context.Background(), ImageRequest{URL: "https://x.example/big.png", Data: big, Budget: 2 * time.Second})

	// Same picture, downscaled and re-encoded: different bytes, same dHash.
	src, _, _ := image.Decode(bytes.NewReader(big))
	small := imaging.Resize(src, 150, 100, imaging.Lanczos)
	var buf bytes.Buffer
	_ = png.Encode(&buf, small)
	before := b.calls.Load()
	a := s.Image(context.Background(), ImageRequest{URL: "https://x.example/small.png", Data: buf.Bytes(), Budget: time.Millisecond})
	if !a.Known || !a.Cached || !a.Adult || b.calls.Load() != before {
		t.Fatalf("near-duplicate should be served from cache: %+v", a)
	}
}

func TestImageBudgetTimeoutThenCacheFills(t *testing.T) {
	b := &fakeBackend{vision: true, delay: 150 * time.Millisecond, imgScore: 0.9}
	b.ready.Store(true)
	s := newTestService(t, b)
	img := testPNG(t, 200, 150, 9)
	a := s.Image(context.Background(), ImageRequest{URL: "https://x.example/a.png", Data: img, Budget: 20 * time.Millisecond})
	if a.Known || !a.TimedOut {
		t.Fatalf("want timeout, got %+v", a)
	}
	time.Sleep(300 * time.Millisecond)
	a = s.Image(context.Background(), ImageRequest{URL: "https://x.example/a.png", Data: img, Budget: time.Millisecond})
	if !a.Known || !a.Cached {
		t.Fatalf("verdict should have landed in the cache after the timeout: %+v", a)
	}
}

func TestPrefiltersAndUnavailable(t *testing.T) {
	b := &fakeBackend{vision: true}
	s := newTestService(t, b) // not ready
	tiny := testPNG(t, 16, 16, 1)
	a := s.Image(context.Background(), ImageRequest{URL: "u", Data: tiny, Budget: time.Second})
	if !a.Known || a.Source != SourcePrefilter || a.Adult {
		t.Fatalf("tiny image should be prefiltered clean: %+v", a)
	}
	a = s.Image(context.Background(), ImageRequest{URL: "u", Data: testPNG(t, 200, 200, 2), Budget: time.Second})
	if !a.Unavailable || a.Known {
		t.Fatalf("model down must report Unavailable: %+v", a)
	}
	a = s.Text(context.Background(), TextRequest{URL: "https://x", Title: "t", Text: "short", Budget: time.Second})
	if !a.Known || a.Source != SourcePrefilter {
		t.Fatalf("short text should be prefiltered: %+v", a)
	}
	if b.calls.Load() != 0 {
		t.Fatal("no model calls expected")
	}
}

func TestQueueFullDrops(t *testing.T) {
	b := &fakeBackend{vision: true, delay: 500 * time.Millisecond, imgScore: 0.1}
	b.ready.Store(true)
	st, _ := OpenMemory()
	defer st.Close()
	s := New(st, b, Options{Workers: 1, QueueLimit: 2, MaxImagePx: 64})
	defer s.Close()
	var dropped int
	for i := 0; i < 6; i++ {
		a := s.Image(context.Background(), ImageRequest{URL: "u", Data: testPNG(t, 100, 100, uint8(i*13+1)), Budget: 0})
		if a.Unavailable {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("expected some requests to be dropped once the queue filled")
	}
}

func TestTextVerdictSiteLearningAndManualOverride(t *testing.T) {
	b := &fakeBackend{vision: true, txtAdult: true}
	b.ready.Store(true)
	s := newTestService(t, b)
	long := "This is a long enough page of text to be classified by the model rather than prefiltered away. "
	for i := 0; i < 3; i++ {
		a := s.Text(context.Background(), TextRequest{URL: "https://www.bad.example/p" + string(rune('a'+i)), Title: "Page", Text: long + string(rune('a'+i)), Budget: time.Second})
		if !a.Known || !a.Adult {
			t.Fatalf("page %d = %+v", i, a)
		}
	}
	// After 3 adult pages the whole site is learned: a never-seen image
	// there is answered without the model.
	before := b.calls.Load()
	a := s.Image(context.Background(), ImageRequest{URL: "https://cdn.bad.example/new.png", Data: testPNG(t, 200, 200, 3), Budget: time.Second})
	if !a.Known || !a.Adult || a.Source != SourceLearned || b.calls.Load() != before {
		t.Fatalf("learned site should answer instantly: %+v", a)
	}
	// Manual override wins and survives a later model verdict.
	if err := s.Override(KindSite, "bad.example", false, "operator says fine"); err != nil {
		t.Fatal(err)
	}
	if d, ok := s.Store().SiteAdult("bad.example"); ok {
		t.Fatalf("site should no longer be adult after override: %+v", d)
	}
	_ = s.Store().Put(Decision{Kind: KindSite, Key: "bad.example", Adult: true, Source: SourceLearned})
	if d, _ := s.Store().Get(KindSite, "bad.example"); d.Adult || d.Source != SourceManual {
		t.Fatalf("manual decision must not be overwritten: %+v", d)
	}
	list, err := s.Store().List("", "bad.example", 10)
	if err != nil || len(list) == 0 {
		t.Fatalf("List = %v, %v", list, err)
	}
	if st := s.Store().Stats(); st.Total == 0 || st.Manual != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestHostVerdict(t *testing.T) {
	b := &fakeBackend{vision: true, hosts: map[string]bool{"ads.example": true}}
	b.ready.Store(true)
	s := newTestService(t, b)
	a := s.Host(context.Background(), HostRequest{Host: "ADS.example", SamplePaths: []string{"/pixel.gif"}, Budget: time.Second})
	if !a.Known || !a.Adult {
		t.Fatalf("host = %+v", a)
	}
	a = s.Host(context.Background(), HostRequest{Host: "cdn.example", Budget: time.Second})
	if !a.Known || a.Adult {
		t.Fatalf("host = %+v", a)
	}
}

func TestSiteOf(t *testing.T) {
	cases := map[string]string{
		"https://www.example.co.uk/a?b": "example.co.uk",
		"cdn.images.example.com":        "example.com",
		"http://10.0.0.5:8080/x":        "10.0.0.5",
		"localhost":                     "localhost",
	}
	for in, want := range cases {
		if got := siteOf(in); got != want {
			t.Errorf("siteOf(%q) = %q, want %q", in, got, want)
		}
	}
}

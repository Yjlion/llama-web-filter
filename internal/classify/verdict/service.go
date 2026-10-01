package verdict

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/yjlion/llama-web-filter/internal/classify/imageprep"
	"github.com/yjlion/llama-web-filter/internal/classify/phash"
	"github.com/yjlion/llama-web-filter/internal/metrics"
)

// Backend is the model behind the service. The llm package's adapter
// implements it; tests use a fake.
type Backend interface {
	// Ready reports whether the model can answer right now.
	Ready() bool
	// ModelID names the model, so cached verdicts can be attributed.
	ModelID() string
	// Vision reports whether image verdicts are possible.
	Vision() bool
	// Image classifies prepared (downscaled JPEG) bytes.
	Image(ctx context.Context, mime string, data []byte, hint string) (Result, error)
	// Text classifies a page's extracted text.
	Text(ctx context.Context, url, title, text string) (Result, error)
	// Host classifies a hostname as ad/tracker or not.
	Host(ctx context.Context, host string, samplePaths []string) (Result, error)
}

// Result is a backend's answer.
type Result struct {
	Score      float64
	Adult      bool
	Confidence float64
	Detail     string
}

// Answer is what callers get: a decision plus how it was reached.
type Answer struct {
	Decision
	// Known is true when a real decision (cache, model, prefilter or
	// manual) exists. When false the caller must fall back to its
	// on_timeout / on_unavailable action.
	Known bool
	// TimedOut means the model is working but the budget elapsed first;
	// the verdict will land in the cache when it finishes.
	TimedOut bool
	// Unavailable means no model is available (down, no vision, queue full).
	Unavailable bool
	// Cached is true for cache hits.
	Cached bool
}

// Options tunes the service.
type Options struct {
	// Workers is how many model calls run concurrently; match the server's
	// parallel slots.
	Workers int
	// QueueLimit bounds pending jobs; beyond it new requests are answered
	// Unavailable rather than queued behind a backlog they would time out on.
	QueueLimit int
	// MaxImagePx is the downscale target for images.
	MaxImagePx int
	// JobTimeout bounds one model call regardless of the caller's budget.
	JobTimeout time.Duration
	// NearDuplicateDistance is the dHash Hamming distance under which two
	// images share a verdict (0 disables).
	NearDuplicateDistance int
}

// Service is the verdict service.
type Service struct {
	store   *Store
	backend Backend
	opts    Options

	mu      sync.Mutex
	jobs    map[string]*job // in-flight, keyed by cacheKey
	queue   []*job
	cond    *sync.Cond
	closed  bool
	workers sync.WaitGroup

	// recent dHashes for near-duplicate lookup; bounded ring.
	hashMu  sync.Mutex
	hashes  []hashEntry
	hashPos int
}

type hashEntry struct {
	h   phash.DHash
	key string
}

type job struct {
	kind     Kind
	key      string
	hint     string
	priority int // lower runs first
	run      func(ctx context.Context) (Result, error)
	done     chan struct{}
	answer   Decision
	err      error
	enqueued time.Time
}

// New builds a service over a store and a backend.
func New(store *Store, backend Backend, opts Options) *Service {
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.QueueLimit <= 0 {
		opts.QueueLimit = 256
	}
	if opts.MaxImagePx <= 0 {
		opts.MaxImagePx = 384
	}
	if opts.JobTimeout <= 0 {
		opts.JobTimeout = 90 * time.Second
	}
	if opts.NearDuplicateDistance == 0 {
		opts.NearDuplicateDistance = 4
	}
	s := &Service{store: store, backend: backend, opts: opts, jobs: map[string]*job{}, hashes: make([]hashEntry, 4096)}
	s.cond = sync.NewCond(&s.mu)
	for i := 0; i < opts.Workers; i++ {
		s.workers.Add(1)
		go s.worker()
	}
	return s
}

// Store exposes the cache for the management API.
func (s *Service) Store() *Store { return s.store }

// Close stops the workers; queued jobs are abandoned.
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	s.workers.Wait()
}

// QueueDepth reports pending jobs, for the status page.
func (s *Service) QueueDepth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}

func (s *Service) worker() {
	defer s.workers.Done()
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closed {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return
		}
		// Pick the highest-priority (lowest number), oldest job.
		best := 0
		for i, j := range s.queue {
			b := s.queue[best]
			if j.priority < b.priority || (j.priority == b.priority && j.enqueued.Before(b.enqueued)) {
				best = i
			}
		}
		j := s.queue[best]
		s.queue = append(s.queue[:best], s.queue[best+1:]...)
		s.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), s.opts.JobTimeout)
		started := time.Now()
		res, err := j.run(ctx)
		cancel()
		metrics.VerdictJobDuration.Observe(time.Since(started).Seconds(), string(j.kind))
		if err == nil {
			j.answer = Decision{Kind: j.kind, Key: j.key, Score: res.Score, Adult: res.Adult, Source: SourceLLM,
				Model: s.backend.ModelID(), Detail: res.Detail, Hint: j.hint, Confidence: res.Confidence, Created: time.Now()}
			if perr := s.store.Put(j.answer); perr != nil {
				slog.Warn("verdict: cache write failed", "err", perr)
			}
			if j.kind != KindHost {
				s.store.RecordSite(siteOf(j.hint), res.Adult)
			}
		} else {
			j.err = err
			metrics.VerdictErrors.Inc(string(j.kind))
		}
		s.mu.Lock()
		delete(s.jobs, cacheKey(j.kind, j.key))
		s.mu.Unlock()
		close(j.done)
	}
}

// ErrQueueFull is returned when the backlog limit is reached.
var ErrQueueFull = errors.New("verdict queue full")

// enqueue registers a job or returns the in-flight one for the same key.
func (s *Service) enqueue(j *job) (*job, error) {
	ck := cacheKey(j.kind, j.key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.jobs[ck]; ok {
		metrics.VerdictCoalesced.Inc(string(j.kind))
		return existing, nil
	}
	if len(s.queue) >= s.opts.QueueLimit {
		metrics.VerdictDropped.Inc(string(j.kind))
		return nil, ErrQueueFull
	}
	j.done = make(chan struct{})
	j.enqueued = time.Now()
	s.jobs[ck] = j
	s.queue = append(s.queue, j)
	s.cond.Signal()
	return j, nil
}

// wait blocks for the job up to budget. A zero budget returns immediately
// (fire-and-forget: the verdict still lands in the cache).
func (s *Service) wait(ctx context.Context, j *job, budget time.Duration) Answer {
	if budget <= 0 {
		return Answer{TimedOut: true}
	}
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case <-j.done:
		if j.err != nil {
			return Answer{Unavailable: true, Decision: Decision{Detail: j.err.Error()}}
		}
		metrics.VerdictOutcomes.Inc(string(j.kind), "model")
		return Answer{Decision: j.answer, Known: true}
	case <-t.C:
		metrics.VerdictOutcomes.Inc(string(j.kind), "timeout")
		return Answer{TimedOut: true}
	case <-ctx.Done():
		return Answer{TimedOut: true}
	}
}

// ImageRequest describes an image to classify.
type ImageRequest struct {
	URL    string
	Data   []byte
	Budget time.Duration
	// Priority: 0 = interactive (a browser is waiting), 1 = speculative.
	Priority int
}

// Image answers for an image: cache (exact bytes, then near-duplicate),
// then the model within the budget.
func (s *Service) Image(ctx context.Context, req ImageRequest) Answer {
	if site, ok := s.store.SiteAdult(siteOf(req.URL)); ok {
		metrics.VerdictOutcomes.Inc("image", "site")
		return Answer{Decision: site, Known: true, Cached: true}
	}
	sum := sha256.Sum256(req.Data)
	exact := hex.EncodeToString(sum[:])
	if d, ok := s.store.Get(KindImage, exact); ok {
		metrics.VerdictOutcomes.Inc("image", "cache")
		return Answer{Decision: d, Known: true, Cached: true}
	}
	prep, err := imageprep.Prepare(req.Data, s.opts.MaxImagePx)
	if err != nil {
		d := Decision{Kind: KindImage, Key: exact, Score: 0, Adult: false, Source: SourcePrefilter, Detail: err.Error(), Hint: req.URL}
		if errors.Is(err, imageprep.ErrTooSmall) {
			_ = s.store.Put(d)
		}
		metrics.VerdictOutcomes.Inc("image", "prefilter")
		return Answer{Decision: d, Known: true}
	}
	// Near-duplicate: same picture at another size/encoding.
	var dh phash.DHash
	if img, _, derr := image.Decode(bytes.NewReader(prep.Data)); derr == nil {
		dh = phash.Compute(img)
		if d, ok := s.store.Get(KindImage, "dh:"+dh.String()); ok {
			_ = s.store.Put(withKey(d, exact))
			metrics.VerdictOutcomes.Inc("image", "cache")
			return Answer{Decision: d, Known: true, Cached: true}
		}
		if key, ok := s.nearest(dh); ok {
			if d, ok := s.store.Get(KindImage, key); ok {
				_ = s.store.Put(withKey(d, exact))
				metrics.VerdictOutcomes.Inc("image", "near")
				return Answer{Decision: d, Known: true, Cached: true}
			}
		}
	}
	if !s.backend.Ready() || !s.backend.Vision() {
		metrics.VerdictOutcomes.Inc("image", "unavailable")
		return Answer{Unavailable: true}
	}
	hint := req.URL
	j := &job{kind: KindImage, key: exact, hint: hint, priority: 1 + req.Priority, run: func(ctx context.Context) (Result, error) {
		res, err := s.backend.Image(ctx, prep.MIME, prep.Data, hostOf(hint))
		if err == nil && dh != 0 {
			s.remember(dh, exact)
			_ = s.store.Put(Decision{Kind: KindImage, Key: "dh:" + dh.String(), Score: res.Score, Adult: res.Adult, Source: SourceLLM,
				Model: s.backend.ModelID(), Detail: res.Detail, Hint: hint, Confidence: res.Confidence, Created: time.Now()})
		}
		return res, err
	}}
	queued, err := s.enqueue(j)
	if err != nil {
		return Answer{Unavailable: true}
	}
	return s.wait(ctx, queued, req.Budget)
}

// TextRequest describes a page to classify.
type TextRequest struct {
	URL    string
	Title  string
	Text   string
	Budget time.Duration
}

// Text answers for a page's text.
func (s *Service) Text(ctx context.Context, req TextRequest) Answer {
	if site, ok := s.store.SiteAdult(siteOf(req.URL)); ok {
		metrics.VerdictOutcomes.Inc("text", "site")
		return Answer{Decision: site, Known: true, Cached: true}
	}
	norm := strings.ToLower(strings.Join(strings.Fields(req.Title+" "+req.Text), " "))
	if len(norm) > 4096 {
		norm = norm[:4096]
	}
	sum := sha256.Sum256([]byte(norm))
	key := hex.EncodeToString(sum[:])
	if d, ok := s.store.Get(KindText, key); ok {
		metrics.VerdictOutcomes.Inc("text", "cache")
		return Answer{Decision: d, Known: true, Cached: true}
	}
	if len(norm) < 100 {
		metrics.VerdictOutcomes.Inc("text", "prefilter")
		return Answer{Decision: Decision{Kind: KindText, Key: key, Source: SourcePrefilter, Detail: "too short"}, Known: true}
	}
	if !s.backend.Ready() {
		metrics.VerdictOutcomes.Inc("text", "unavailable")
		return Answer{Unavailable: true}
	}
	url, title, text := req.URL, req.Title, req.Text
	j := &job{kind: KindText, key: key, hint: url, priority: 0, run: func(ctx context.Context) (Result, error) {
		return s.backend.Text(ctx, url, title, text)
	}}
	queued, err := s.enqueue(j)
	if err != nil {
		return Answer{Unavailable: true}
	}
	return s.wait(ctx, queued, req.Budget)
}

// HostRequest describes a hostname to classify as ad/tracker.
type HostRequest struct {
	Host        string
	SamplePaths []string
	Budget      time.Duration
}

// Host answers whether a host is an ad/tracker host (Adult=true means
// "block it" for this kind; Score is the confidence).
func (s *Service) Host(ctx context.Context, req HostRequest) Answer {
	key := strings.ToLower(strings.TrimSpace(req.Host))
	if d, ok := s.store.Get(KindHost, key); ok {
		metrics.VerdictOutcomes.Inc("host", "cache")
		return Answer{Decision: d, Known: true, Cached: true}
	}
	if !s.backend.Ready() {
		return Answer{Unavailable: true}
	}
	paths := req.SamplePaths
	j := &job{kind: KindHost, key: key, hint: key, priority: 2, run: func(ctx context.Context) (Result, error) {
		return s.backend.Host(ctx, key, paths)
	}}
	queued, err := s.enqueue(j)
	if err != nil {
		return Answer{Unavailable: true}
	}
	return s.wait(ctx, queued, req.Budget)
}

// Override records an operator decision that wins over everything.
func (s *Service) Override(kind Kind, key string, adult bool, note string) error {
	score := 0.0
	if adult {
		score = 1
	}
	return s.store.Put(Decision{Kind: kind, Key: key, Score: score, Adult: adult, Source: SourceManual, Detail: note, Confidence: 1, Created: time.Now()})
}

func (s *Service) remember(h phash.DHash, key string) {
	s.hashMu.Lock()
	s.hashes[s.hashPos] = hashEntry{h: h, key: key}
	s.hashPos = (s.hashPos + 1) % len(s.hashes)
	s.hashMu.Unlock()
}

func (s *Service) nearest(h phash.DHash) (string, bool) {
	if s.opts.NearDuplicateDistance <= 0 {
		return "", false
	}
	s.hashMu.Lock()
	defer s.hashMu.Unlock()
	for _, e := range s.hashes {
		if e.key != "" && e.h.Distance(h) <= s.opts.NearDuplicateDistance {
			return e.key, true
		}
	}
	return "", false
}

func withKey(d Decision, key string) Decision {
	d.Key = key
	return d
}

// siteOf reduces a URL or host to its registrable domain (eTLD+1).
func siteOf(urlOrHost string) string {
	h := hostOf(urlOrHost)
	if h == "" || net.ParseIP(h) != nil {
		return h
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return d
	}
	return h
}

func hostOf(urlOrHost string) string {
	s := strings.TrimSpace(urlOrHost)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

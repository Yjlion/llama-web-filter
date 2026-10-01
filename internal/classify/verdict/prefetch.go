package verdict

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Prefetcher scores images referenced by a page before the browser asks for
// them, so the image requests that follow hit a warm cache. It is
// best-effort and bounded: a few concurrent fetches, a size cap, and a
// short memory of URLs already seen.
type Prefetcher struct {
	svc    *Service
	client *http.Client
	sem    chan struct{}

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewPrefetcher builds a prefetcher using client for upstream fetches.
func NewPrefetcher(svc *Service, client *http.Client, concurrency int) *Prefetcher {
	if concurrency <= 0 {
		concurrency = 2
	}
	return &Prefetcher{svc: svc, client: client, sem: make(chan struct{}, concurrency), seen: map[string]time.Time{}}
}

// MaxPrefetchBytes caps one fetched image.
const MaxPrefetchBytes = 4 << 20

// Prefetch resolves srcs against page and scores up to limit of them in the
// background. Headers carries the page request's User-Agent and Referer
// so origins that key on them serve the same bytes the browser will get.
func (p *Prefetcher) Prefetch(page *url.URL, srcs []string, limit int, headers http.Header) {
	if p == nil || p.svc == nil || !p.svc.backend.Ready() || !p.svc.backend.Vision() {
		return
	}
	n := 0
	for _, src := range srcs {
		if n >= limit {
			break
		}
		ref, err := url.Parse(strings.TrimSpace(src))
		if err != nil {
			continue
		}
		abs := page.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			continue
		}
		u := abs.String()
		if !p.mark(u) {
			continue
		}
		n++
		go p.fetchAndScore(u, headers)
	}
}

func (p *Prefetcher) mark(u string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if len(p.seen) > 4096 {
		for k, t := range p.seen {
			if now.Sub(t) > 10*time.Minute {
				delete(p.seen, k)
			}
		}
	}
	if t, ok := p.seen[u]; ok && now.Sub(t) < 10*time.Minute {
		return false
	}
	p.seen[u] = now
	return true
}

func (p *Prefetcher) fetchAndScore(u string, headers http.Header) {
	p.sem <- struct{}{}
	defer func() { <-p.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	for _, h := range []string{"User-Agent", "Referer", "Accept-Language"} {
		if v := headers.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set("Accept", "image/*")
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxPrefetchBytes+1))
	if err != nil || len(data) > MaxPrefetchBytes {
		return
	}
	// Zero budget: enqueue and return; the verdict lands in the cache.
	p.svc.Image(context.Background(), ImageRequest{URL: u, Data: data, Budget: 0, Priority: 1})
}

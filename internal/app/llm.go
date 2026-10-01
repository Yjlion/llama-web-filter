package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/classify/imageprep"
	"github.com/yjlion/llama-web-filter/internal/classify/verdict"
	"github.com/yjlion/llama-web-filter/internal/llm"
	"github.com/yjlion/llama-web-filter/internal/llm/catalog"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
)

// LLMStack is everything the LLM contributes to a running process: the
// service that owns llama-server, the verdict service that caches and
// queues decisions in front of it, and the adapters the pipeline and the
// management API talk to.
type LLMStack struct {
	Svc      *llm.Service
	Verdicts *verdict.Service
	Store    *verdict.Store
	Prefetch *verdict.Prefetcher
	adapter  *llmBackend
}

// NewLLMStack builds and starts the stack for settings. It never fails the
// caller: a runtime that cannot start is reported on the LLM page and the
// proxy runs with classification unavailable (the configured
// on_unavailable actions apply).
func NewLLMStack(ctx context.Context, cfg models.LLMConfig) *LLMStack {
	svc := llm.New(cfg)
	if !cfg.Enabled {
		slog.Info("llm: disabled in settings; content classification unavailable")
	} else if err := svc.Start(ctx); err != nil {
		slog.Error("llm: start failed; content classification unavailable until fixed", "err", err)
	} else if rt, m := svc.Missing(); (rt || m) && cfg.ExternalURL == "" {
		slog.Warn("llm: runtime or model not installed; run `webfilter llm download` or use the LLM page", "runtime_missing", rt, "model_missing", m)
	}

	dbPath := ":memory:"
	if cfg.DataDir != "" {
		dbPath = filepath.Join(cfg.DataDir, "decisions.db")
	}
	store, err := verdict.Open(dbPath, 50000)
	if err != nil {
		slog.Error("verdict: cannot open decision cache, using memory", "err", err, "path", dbPath)
		store, _ = verdict.OpenMemory()
	}
	backend := &llmBackend{svc: svc, maxPx: cfg.MaxImagePx}
	vs := verdict.New(store, backend, verdict.Options{
		Workers:    cfg.ParallelSlots,
		QueueLimit: 64 * max(cfg.ParallelSlots, 1),
		MaxImagePx: cfg.MaxImagePx,
	})
	pre := verdict.NewPrefetcher(vs, &http.Client{Transport: proxy.NewTransport(), Timeout: 20 * time.Second}, 2)
	return &LLMStack{Svc: svc, Verdicts: vs, Store: store, Prefetch: pre, adapter: backend}
}

// Close stops the model and the verdict workers.
func (st *LLMStack) Close() {
	st.Verdicts.Close()
	st.Svc.Stop()
	_ = st.Store.Close()
}

// PipelineClassifiers is what BuildProxyEngine wires into the addons.
func (st *LLMStack) PipelineClassifiers() Classifiers {
	return Classifiers{Classifier: &pipelineClassifier{vs: st.Verdicts}, Prefetcher: st.Prefetch, Fetcher: st.Prefetch}
}

// Scanner is the management API's content scanner.
func (st *LLMStack) Scanner() mgmtapi.ContentScanner { return &scanner{st: st} }

// Controller is the management API's LLM controller.
func (st *LLMStack) Controller() mgmtapi.LLMController {
	return &controller{svc: st.Svc, vs: st.Verdicts}
}

// Decisions is the management API's decision-cache view.
func (st *LLMStack) Decisions() mgmtapi.DecisionStore { return &decisions{vs: st.Verdicts} }

// ---- verdict.Backend over llm.Service ----

type llmBackend struct {
	svc   *llm.Service
	maxPx int
}

func (b *llmBackend) Ready() bool     { return b.svc.Ready() }
func (b *llmBackend) ModelID() string { return b.svc.Model().ID }
func (b *llmBackend) Vision() bool    { return b.svc.Model().Vision }

// ErrLLMNotReady is returned while the model is down.
var ErrLLMNotReady = errors.New("LLM is not ready")

func (b *llmBackend) Image(ctx context.Context, mime string, data []byte, hint string) (verdict.Result, error) {
	cli := b.svc.Client()
	if cli == nil {
		return verdict.Result{}, ErrLLMNotReady
	}
	started := time.Now()
	v, _, err := cli.ClassifyImage(ctx, mime, data, hint)
	llm.Observe("image", started, err)
	if err != nil {
		return verdict.Result{}, err
	}
	detail := v.Description
	if v.IsAd {
		detail = "[ad] " + detail
	}
	return verdict.Result{Score: v.Score(), Adult: v.Adult || v.Nudity >= 2, Confidence: v.Confidence, Detail: detail}, nil
}

func (b *llmBackend) Text(ctx context.Context, url, title, text string) (verdict.Result, error) {
	cli := b.svc.Client()
	if cli == nil {
		return verdict.Result{}, ErrLLMNotReady
	}
	started := time.Now()
	v, _, err := cli.ClassifyText(ctx, url, title, text)
	llm.Observe("text", started, err)
	if err != nil {
		return verdict.Result{}, err
	}
	detail := v.Reason
	if len(v.Categories) > 0 {
		detail = strings.Join(v.Categories, ",") + ": " + detail
	}
	return verdict.Result{Score: v.Score(), Adult: v.Adult, Confidence: v.Confidence, Detail: detail}, nil
}

func (b *llmBackend) Host(ctx context.Context, host string, samplePaths []string) (verdict.Result, error) {
	cli := b.svc.Client()
	if cli == nil {
		return verdict.Result{}, ErrLLMNotReady
	}
	started := time.Now()
	v, _, err := cli.ClassifyHost(ctx, host, samplePaths)
	llm.Observe("host", started, err)
	if err != nil {
		return verdict.Result{}, err
	}
	score := v.Confidence
	if !v.IsAdOrTracker {
		score = 1 - v.Confidence
	}
	return verdict.Result{Score: score, Adult: v.IsAdOrTracker, Confidence: v.Confidence, Detail: v.Category}, nil
}

// ---- addons.ContentClassifier over verdict.Service ----

type pipelineClassifier struct{ vs *verdict.Service }

func toVerdict(a verdict.Answer) addons.Verdict {
	return addons.Verdict{Known: a.Known, Score: a.Score, Adult: a.Adult, Source: string(a.Source), Detail: a.Detail, TimedOut: a.TimedOut, Unavailable: a.Unavailable}
}

func (c *pipelineClassifier) ClassifyText(ctx context.Context, req addons.TextRequest) addons.Verdict {
	return toVerdict(c.vs.Text(ctx, verdict.TextRequest{URL: req.URL, Title: req.Title, Text: req.Text, Budget: req.Budget}))
}

func (c *pipelineClassifier) ClassifyImage(ctx context.Context, req addons.ImageRequest) addons.Verdict {
	return toVerdict(c.vs.Image(ctx, verdict.ImageRequest{URL: req.URL, Data: req.Data, Budget: req.Budget}))
}

func (c *pipelineClassifier) ClassifyHost(ctx context.Context, req addons.HostRequest) addons.Verdict {
	return toVerdict(c.vs.Host(ctx, verdict.HostRequest{Host: req.Host, SamplePaths: req.SamplePaths, Budget: req.Budget}))
}

// ---- mgmtapi.ContentScanner (Tools page) ----

type scanner struct{ st *LLMStack }

func (s *scanner) ScanText(ctx context.Context, text string) (mgmtapi.TextScan, error) {
	if !s.st.Svc.Ready() {
		return mgmtapi.TextScan{}, ErrLLMNotReady
	}
	a := s.st.Verdicts.Text(ctx, verdict.TextRequest{URL: "", Title: "", Text: text, Budget: 60 * time.Second})
	if !a.Known {
		return mgmtapi.TextScan{}, fmt.Errorf("no verdict: %s", a.Detail)
	}
	return mgmtapi.TextScan{Adult: a.Adult, Score: a.Score, Categories: splitDetail(a.Detail), Source: string(a.Source)}, nil
}

func splitDetail(d string) []string {
	cats, _, ok := strings.Cut(d, ": ")
	if !ok {
		return nil
	}
	return strings.Split(cats, ",")
}

func (s *scanner) ScanImage(ctx context.Context, img []byte) (mgmtapi.ImageScan, error) {
	if !s.st.Svc.Ready() {
		return mgmtapi.ImageScan{}, ErrLLMNotReady
	}
	if !s.st.Svc.Model().Vision {
		return mgmtapi.ImageScan{}, fmt.Errorf("model %s has no vision support", s.st.Svc.Model().ID)
	}
	if _, err := imageprep.Prepare(img, s.st.adapter.maxPx); err != nil {
		return mgmtapi.ImageScan{}, err
	}
	a := s.st.Verdicts.Image(ctx, verdict.ImageRequest{URL: "tools-scan", Data: img, Budget: 60 * time.Second})
	if !a.Known {
		return mgmtapi.ImageScan{}, fmt.Errorf("no verdict: %s", a.Detail)
	}
	return mgmtapi.ImageScan{
		Adult: a.Adult, Score: a.Score, Source: string(a.Source),
		Detections: []map[string]any{
			{"class": "adult", "score": a.Score},
			{"class": "description", "text": a.Detail},
		},
	}, nil
}

func (s *scanner) Health(ctx context.Context) mgmtapi.ScannerHealth {
	st := s.st.Svc.Status()
	h := mgmtapi.ScannerHealth{Model: st.Model, Status: string(st.Phase), Detail: st.LastError}
	h.Available = st.Phase == llm.PhaseReady
	if h.Available && h.Detail == "" {
		h.Detail = "model loaded and answering"
	}
	return h
}

// ---- mgmtapi.LLMController ----

type controller struct {
	svc *llm.Service
	vs  *verdict.Service
}

func (c *controller) Status() any {
	st := c.svc.Status()
	return struct {
		llm.Status
		QueueDepth int           `json:"queue_depth"`
		Cache      verdict.Stats `json:"cache"`
	}{st, c.vs.QueueDepth(), c.vs.Store().Stats()}
}
func (c *controller) Catalog() any    { return catalog.All() }
func (c *controller) CancelDownload() { c.svc.CancelDownload() }
func (c *controller) Download(ctx context.Context, model string) error {
	return c.svc.Download(ctx, strings.TrimSpace(model))
}
func (c *controller) Restart(ctx context.Context) error { return c.svc.Restart(ctx) }
func (c *controller) RemoveModel(id string) error       { return c.svc.RemoveModel(id) }
func (c *controller) LogTail(n int64) string            { return c.svc.LogTail(n) }

// ---- mgmtapi.DecisionStore ----

type decisions struct{ vs *verdict.Service }

func (d *decisions) List(kind, query string, limit int) (any, error) {
	return d.vs.Store().List(verdict.Kind(kind), query, limit)
}
func (d *decisions) Override(kind, key string, adult bool, note string) error {
	return d.vs.Override(verdict.Kind(kind), key, adult, note)
}
func (d *decisions) Delete(kind, key string) error {
	return d.vs.Store().Delete(verdict.Kind(kind), key)
}
func (d *decisions) Clear(kind string, includeManual bool) error {
	return d.vs.Store().Clear(verdict.Kind(kind), includeManual)
}
func (d *decisions) Stats() any { return d.vs.Store().Stats() }

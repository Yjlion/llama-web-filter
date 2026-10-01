package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/classify/imageprep"
	"github.com/yjlion/llama-web-filter/internal/llm"
	"github.com/yjlion/llama-web-filter/internal/llm/catalog"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// LLMAdapter presents an llm.Service to the management API (as a
// ContentScanner and an LLMController). It is the one place the management
// API's DTO shapes and the service's types meet.
type LLMAdapter struct {
	Svc *llm.Service
}

var _ mgmtapi.ContentScanner = (*LLMAdapter)(nil)
var _ mgmtapi.LLMController = (*LLMAdapter)(nil)

// NewLLMService builds and starts the LLM service for settings; it never
// fails the caller - a runtime that cannot start is reported on the LLM
// page and the proxy runs with classification unavailable.
func NewLLMService(ctx context.Context, cfg models.LLMConfig) *llm.Service {
	svc := llm.New(cfg)
	if !cfg.Enabled {
		slog.Info("llm: disabled in settings; content classification unavailable")
		return svc
	}
	if err := svc.Start(ctx); err != nil {
		slog.Error("llm: start failed; content classification unavailable until fixed", "err", err)
	} else if rt, m := svc.Missing(); rt || m {
		slog.Warn("llm: runtime or model not installed; run `webfilter llm download` or use the LLM page", "runtime_missing", rt, "model_missing", m)
	}
	return svc
}

// ErrLLMNotReady is returned by the scanner while the model is down.
var ErrLLMNotReady = errors.New("LLM is not ready")

func (a *LLMAdapter) ScanText(ctx context.Context, text string) (mgmtapi.TextScan, error) {
	cli := a.Svc.Client()
	if cli == nil {
		return mgmtapi.TextScan{}, ErrLLMNotReady
	}
	started := time.Now()
	v, _, err := cli.ClassifyText(ctx, "", "", text)
	llm.Observe("text", started, err)
	if err != nil {
		return mgmtapi.TextScan{}, err
	}
	return mgmtapi.TextScan{Adult: v.Adult, Score: v.Score(), Categories: v.Categories, Source: "llm"}, nil
}

func (a *LLMAdapter) ScanImage(ctx context.Context, img []byte) (mgmtapi.ImageScan, error) {
	cli := a.Svc.Client()
	if cli == nil {
		return mgmtapi.ImageScan{}, ErrLLMNotReady
	}
	if !a.Svc.Model().Vision {
		return mgmtapi.ImageScan{}, fmt.Errorf("model %s has no vision support", a.Svc.Model().ID)
	}
	prep, err := imageprep.Prepare(img, a.Svc.Config().MaxImagePx)
	if err != nil {
		return mgmtapi.ImageScan{}, err
	}
	started := time.Now()
	v, _, err := cli.ClassifyImage(ctx, prep.MIME, prep.Data, "")
	llm.Observe("image", started, err)
	if err != nil {
		return mgmtapi.ImageScan{}, err
	}
	return mgmtapi.ImageScan{
		Adult: v.Adult, Score: v.Score(), Source: "llm",
		Detections: []map[string]any{
			{"class": "adult", "score": v.Score()},
			{"class": "nudity_level", "score": float64(v.Nudity) / 3},
			{"class": "violence_level", "score": float64(v.Violence) / 3},
			{"class": "advertisement", "score": boolScore(v.IsAd)},
			{"class": "description", "text": v.Description},
		},
	}, nil
}

func boolScore(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (a *LLMAdapter) Health(ctx context.Context) mgmtapi.ScannerHealth {
	st := a.Svc.Status()
	h := mgmtapi.ScannerHealth{Model: st.Model, Status: string(st.Phase), Detail: st.LastError}
	h.Available = st.Phase == llm.PhaseReady
	if h.Available && h.Detail == "" {
		h.Detail = "model loaded and answering"
	}
	return h
}

func (a *LLMAdapter) Status() any    { return a.Svc.Status() }
func (a *LLMAdapter) Catalog() any   { return catalog.All() }
func (a *LLMAdapter) CancelDownload() { a.Svc.CancelDownload() }
func (a *LLMAdapter) Download(ctx context.Context, model string) error {
	return a.Svc.Download(ctx, strings.TrimSpace(model))
}
func (a *LLMAdapter) Restart(ctx context.Context) error { return a.Svc.Restart(ctx) }
func (a *LLMAdapter) RemoveModel(id string) error        { return a.Svc.RemoveModel(id) }
func (a *LLMAdapter) LogTail(n int64) string             { return a.Svc.LogTail(n) }

// Classifiers for the addon pipeline are produced in M3 by the verdict
// service; until then the pipeline's text/image backends stay nil.
func (a *LLMAdapter) PipelineClassifiers() Classifiers {
	return Classifiers{Text: nil, Image: nil}
}

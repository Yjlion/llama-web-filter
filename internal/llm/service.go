// Package llm ties the runtime, catalog and client together into one
// Service the rest of the filter talks to: "is the model up", "download
// this model", "classify this image".
package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yjlion/llama-web-filter/internal/llm/catalog"
	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/llm/runtime"
	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// Service is the process-wide LLM facade.
type Service struct {
	cfg   models.LLMConfig
	hub   *catalog.Hub
	accel runtime.Accel

	mu        sync.Mutex
	sup       *runtime.Supervisor
	cli       *client.Client
	external  bool
	model     catalog.Model
	installed *catalog.Installed
	rt        *runtime.Installed
	phase     Phase
	lastErr   string
	dl        *download
	cancelSup context.CancelFunc
	warm      bool
	warmMs    int
}

// Phase is the service's coarse state for the status page.
type Phase string

const (
	PhaseDisabled      Phase = "disabled"
	PhaseNeedsDownload Phase = "needs_download"
	PhaseDownloading   Phase = "downloading"
	PhaseStarting      Phase = "starting"
	PhaseReady         Phase = "ready"
	PhaseFailed        Phase = "failed"
	PhaseStopped       Phase = "stopped"
)

type download struct {
	what     string // "runtime" or model id
	prog     *catalog.Progress
	step     string
	started  time.Time
	done     bool
	err      string
	cancel   context.CancelFunc
	finished time.Time
}

// New builds a Service from settings. Nothing runs until Start.
func New(cfg models.LLMConfig) *Service {
	s := &Service{cfg: cfg, hub: catalog.NewHub(), accel: runtime.ResolveAccel(cfg.Accel)}
	if !cfg.Enabled {
		s.phase = PhaseDisabled
	} else {
		s.phase = PhaseStopped
	}
	if m, ok := catalog.Lookup(cfg.Model); ok {
		s.model = m
	} else {
		s.model, _ = catalog.Lookup(models.DefaultLLMModel)
		s.lastErr = fmt.Sprintf("unknown model %q in settings, using %s", cfg.Model, s.model.ID)
	}
	return s
}

// Config returns the settings the service was built from.
func (s *Service) Config() models.LLMConfig { return s.cfg }

// Model is the configured catalog entry.
func (s *Service) Model() catalog.Model { return s.model }

// Accel is the resolved build flavour.
func (s *Service) Accel() runtime.Accel { return s.accel }

// DataDir is the runtime/model directory.
func (s *Service) DataDir() string { return s.cfg.DataDir }

// Start brings the model up if everything it needs is on disk. When the
// runtime or model is missing it does not download (that can be gigabytes
// and belongs behind an explicit action or the setup wizard); the phase
// becomes needs_download and Download can be called later, after which
// the service starts itself.
func (s *Service) Start(ctx context.Context) error {
	if !s.cfg.Enabled {
		return nil
	}
	if s.cfg.ExternalURL != "" {
		s.mu.Lock()
		s.external = true
		s.cli = client.New(s.cfg.ExternalURL)
		s.phase = PhaseStarting
		s.mu.Unlock()
		go s.watchExternal(ctx)
		return nil
	}
	if !s.installedOK() {
		s.mu.Lock()
		s.phase = PhaseNeedsDownload
		s.mu.Unlock()
		return nil
	}
	return s.spawn(ctx)
}

func (s *Service) installedOK() bool {
	rt, ok := runtime.LoadInstalled(s.cfg.DataDir, runtime.PinnedTag, s.accel)
	if !ok {
		return false
	}
	inst, ok := catalog.LoadInstalled(s.cfg.DataDir, s.model.ID)
	if !ok {
		return false
	}
	s.mu.Lock()
	s.rt = &rt
	s.installed = &inst
	s.mu.Unlock()
	return true
}

// Missing reports which pieces still need downloading.
func (s *Service) Missing() (runtimeMissing, modelMissing bool) {
	_, rok := runtime.LoadInstalled(s.cfg.DataDir, runtime.PinnedTag, s.accel)
	_, mok := catalog.LoadInstalled(s.cfg.DataDir, s.model.ID)
	return !rok, !mok
}

func (s *Service) spawn(ctx context.Context) error {
	s.mu.Lock()
	if s.sup != nil {
		s.mu.Unlock()
		return nil
	}
	rt, inst := s.rt, s.installed
	s.phase = PhaseStarting
	s.lastErr = ""
	dir := catalog.ModelDir(s.cfg.DataDir, inst.ID)
	spec := runtime.Spec{
		Server:    rt.Server,
		ModelPath: filepath.Join(dir, inst.ModelFile),
		Port:      s.cfg.Port,
		Threads:   s.cfg.Threads,
		GPULayers: s.cfg.GPULayers,
		Slots:     s.cfg.ParallelSlots,
		Context:   s.cfg.ContextSize,
		ExtraArgs: s.cfg.ExtraArgs,
		LogPath:   filepath.Join(s.cfg.DataDir, "llama-server.log"),
	}
	if inst.MMProjFile != "" {
		spec.MMProj = filepath.Join(dir, inst.MMProjFile)
	}
	if s.accel == runtime.AccelCPU || s.accel == runtime.AccelMetal {
		// nothing to offload on CPU; Metal offloads by default
	}
	sup := runtime.New(spec)
	s.sup = sup
	supCtx, cancel := context.WithCancel(ctx)
	s.cancelSup = cancel
	s.mu.Unlock()

	if err := sup.Start(supCtx); err != nil {
		s.mu.Lock()
		s.phase = PhaseFailed
		s.lastErr = err.Error()
		s.sup = nil
		s.mu.Unlock()
		cancel()
		return err
	}
	s.mu.Lock()
	s.cli = client.New(sup.BaseURL())
	s.phase = PhaseReady
	s.mu.Unlock()
	go s.warmup(supCtx)
	return nil
}

// watchExternal polls an external server's health so the status page is
// honest about it.
func (s *Service) watchExternal(ctx context.Context) {
	for {
		ok := s.cli.Healthy(ctx)
		s.mu.Lock()
		if ok {
			s.phase = PhaseReady
			s.lastErr = ""
		} else {
			s.phase = PhaseFailed
			s.lastErr = "external server not healthy: " + s.cfg.ExternalURL
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

// warmup sends one tiny request so the first real verdict does not pay
// for lazy initialisation, and records how long it took.
func (s *Service) warmup(ctx context.Context) {
	cli := s.Client()
	if cli == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	started := time.Now()
	_, _, err := cli.ClassifyText(ctx, "https://example.com/", "Example Domain", "This domain is for use in illustrative examples in documents.")
	s.mu.Lock()
	s.warm = err == nil
	s.warmMs = int(time.Since(started).Milliseconds())
	s.mu.Unlock()
	if err != nil {
		slog.Warn("llm warm-up failed", "err", err)
	} else {
		slog.Info("llm warm-up complete", "ms", s.warmMs)
	}
}

// Client returns the chat client, or nil when the model is not ready.
func (s *Service) Client() *client.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != PhaseReady {
		return nil
	}
	return s.cli
}

// Ready reports whether verdicts can be requested right now.
func (s *Service) Ready() bool { return s.Client() != nil }

// Stop terminates the managed server.
func (s *Service) Stop() {
	s.mu.Lock()
	sup, cancel := s.sup, s.cancelSup
	s.sup, s.cancelSup = nil, nil
	s.phase = PhaseStopped
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sup != nil {
		sup.Stop()
	}
}

// Restart stops and starts the managed server.
func (s *Service) Restart(ctx context.Context) error {
	s.Stop()
	return s.Start(ctx)
}

// ErrBusy is returned when a download is already running.
var ErrBusy = errors.New("a download is already in progress")

// Download fetches the runtime and/or the given model (empty = configured
// model) in the background, then starts the service if it was waiting.
// ctx is the long-lived process context; the download has its own cancel.
func (s *Service) Download(ctx context.Context, modelID string) error {
	if modelID == "" {
		modelID = s.model.ID
	}
	m, ok := catalog.Lookup(modelID)
	if !ok {
		return fmt.Errorf("unknown model %q (known: %v)", modelID, catalog.IDs())
	}
	s.mu.Lock()
	if s.dl != nil && !s.dl.done {
		s.mu.Unlock()
		return ErrBusy
	}
	dctx, cancel := context.WithCancel(ctx)
	d := &download{what: m.ID, prog: &catalog.Progress{}, started: time.Now(), cancel: cancel}
	s.dl = d
	if s.phase == PhaseNeedsDownload || s.phase == PhaseStopped {
		s.phase = PhaseDownloading
	}
	s.mu.Unlock()

	go func() {
		err := s.runDownload(dctx, d, m)
		s.mu.Lock()
		d.done = true
		d.finished = time.Now()
		if err != nil {
			d.err = err.Error()
			s.lastErr = err.Error()
			if s.phase == PhaseDownloading {
				s.phase = PhaseNeedsDownload
			}
		}
		waiting := err == nil && m.ID == s.model.ID && s.sup == nil && !s.external && s.cfg.Enabled
		if waiting {
			s.phase = PhaseStopped
		}
		s.mu.Unlock()
		if waiting && s.installedOK() {
			if err := s.spawn(ctx); err != nil {
				slog.Error("llm start after download failed", "err", err)
			}
		}
	}()
	return nil
}

func (s *Service) runDownload(ctx context.Context, d *download, m catalog.Model) error {
	if err := os.MkdirAll(s.cfg.DataDir, 0o755); err != nil {
		return err
	}
	if _, ok := runtime.LoadInstalled(s.cfg.DataDir, runtime.PinnedTag, s.accel); !ok {
		s.setStep(d, "runtime: resolving llama.cpp "+runtime.PinnedTag)
		rt, err := runtime.Download(ctx, s.cfg.DataDir, runtime.PinnedTag, s.accel, func(step string) { s.setStep(d, "runtime: "+step) })
		if err != nil {
			if s.accel != runtime.AccelCPU && s.accel != runtime.AccelMetal {
				// A GPU build that cannot be fetched should not strand the user.
				slog.Warn("llm runtime download failed, falling back to CPU build", "accel", s.accel, "err", err)
				s.accel = runtime.AccelCPU
				rt, err = runtime.Download(ctx, s.cfg.DataDir, runtime.PinnedTag, s.accel, func(step string) { s.setStep(d, "runtime: "+step) })
			}
			if err != nil {
				return fmt.Errorf("runtime: %w", err)
			}
		}
		s.mu.Lock()
		s.rt = &rt
		s.mu.Unlock()
	}
	if _, ok := catalog.LoadInstalled(s.cfg.DataDir, m.ID); !ok {
		s.setStep(d, "model: resolving "+m.ID)
		inst, err := s.hub.Download(ctx, s.cfg.DataDir, m, d.prog)
		if err != nil {
			return fmt.Errorf("model %s: %w", m.ID, err)
		}
		if m.ID == s.model.ID {
			s.mu.Lock()
			s.installed = &inst
			s.mu.Unlock()
		}
	}
	s.setStep(d, "done")
	return nil
}

func (s *Service) setStep(d *download, step string) {
	s.mu.Lock()
	d.step = step
	s.mu.Unlock()
}

// CancelDownload aborts a running download.
func (s *Service) CancelDownload() {
	s.mu.Lock()
	d := s.dl
	s.mu.Unlock()
	if d != nil && !d.done && d.cancel != nil {
		d.cancel()
	}
}

// DownloadStatus is the live download view.
type DownloadStatus struct {
	Active    bool    `json:"active"`
	What      string  `json:"what,omitempty"`
	Step      string  `json:"step,omitempty"`
	BytesDone int64   `json:"bytes_done"`
	BytesTot  int64   `json:"bytes_total"`
	File      string  `json:"file,omitempty"`
	Percent   float64 `json:"percent"`
	Error     string  `json:"error,omitempty"`
	Seconds   float64 `json:"seconds"`
}

// Status is the full status payload for the UI and CLI.
type Status struct {
	Enabled      bool                `json:"enabled"`
	Phase        Phase               `json:"phase"`
	Model        string              `json:"model"`
	ModelName    string              `json:"model_name"`
	Vision       bool                `json:"vision"`
	Accel        string              `json:"accel"`
	External     string              `json:"external_url,omitempty"`
	DataDir      string              `json:"data_dir"`
	RuntimeTag   string              `json:"runtime_tag"`
	RuntimeReady bool                `json:"runtime_installed"`
	ModelReady   bool                `json:"model_installed"`
	ModelFile    string              `json:"model_file,omitempty"`
	ModelSizeMB  int64               `json:"model_size_mb,omitempty"`
	Server       *runtime.Status     `json:"server,omitempty"`
	Download     DownloadStatus      `json:"download"`
	LastError    string              `json:"last_error,omitempty"`
	Warm         bool                `json:"warm"`
	WarmupMs     int                 `json:"warmup_ms,omitempty"`
	Installed    []catalog.Installed `json:"installed_models"`
	Budget       models.LLMBudget    `json:"budget"`
}

// Status snapshots the service.
func (s *Service) Status() Status {
	rtMissing, mMissing := s.Missing()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled:      s.cfg.Enabled,
		Phase:        s.phase,
		Model:        s.model.ID,
		ModelName:    s.model.Name,
		Vision:       s.model.Vision,
		Accel:        string(s.accel),
		External:     s.cfg.ExternalURL,
		DataDir:      s.cfg.DataDir,
		RuntimeTag:   runtime.PinnedTag,
		RuntimeReady: !rtMissing,
		ModelReady:   !mMissing,
		LastError:    s.lastErr,
		Warm:         s.warm,
		WarmupMs:     s.warmMs,
		Installed:    catalog.ListInstalled(s.cfg.DataDir),
		Budget:       s.cfg.Budget,
	}
	if st.Installed == nil {
		st.Installed = []catalog.Installed{}
	}
	if s.installed != nil {
		st.ModelFile = s.installed.ModelFile
		st.ModelSizeMB = s.installed.SizeBytes >> 20
	}
	if s.sup != nil {
		ss := s.sup.Status()
		st.Server = &ss
	}
	if d := s.dl; d != nil {
		st.Download = DownloadStatus{
			Active: !d.done, What: d.what, Step: d.step, Error: d.err,
			BytesDone: d.prog.Done(), BytesTot: d.prog.Total, File: d.prog.Current(),
		}
		end := d.finished
		if !d.done {
			end = time.Now()
		}
		st.Download.Seconds = end.Sub(d.started).Seconds()
		if st.Download.BytesTot > 0 {
			st.Download.Percent = 100 * float64(st.Download.BytesDone) / float64(st.Download.BytesTot)
		}
	}
	return st
}

// LogTail returns the last n bytes of the llama-server log.
func (s *Service) LogTail(n int64) string {
	p := filepath.Join(s.cfg.DataDir, "llama-server.log")
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err.Error() != "EOF" {
		return ""
	}
	return string(buf)
}

// RemoveModel deletes an installed model that is not the one in use.
func (s *Service) RemoveModel(id string) error {
	if id == s.model.ID {
		return errors.New("cannot remove the model currently configured; switch models first")
	}
	return catalog.Remove(s.cfg.DataDir, id)
}

// Observe records one classification call in the metrics registry.
func Observe(kind string, started time.Time, err error) {
	result := "ok"
	if err != nil {
		if errors.Is(err, client.ErrUnavailable) {
			result = "unavailable"
		} else if errors.Is(err, context.DeadlineExceeded) {
			result = "timeout"
		} else {
			result = "error"
		}
	}
	metrics.LLMRequests.Inc(kind, result)
	metrics.LLMDuration.Observe(time.Since(started).Seconds(), kind)
}

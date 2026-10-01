package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Spec is everything needed to launch one llama-server.
type Spec struct {
	Server    string // path to llama-server
	ModelPath string
	MMProj    string // empty for text-only models
	Port      int    // 0 = pick a free loopback port
	Threads   int
	GPULayers int
	Slots     int
	Context   int
	ExtraArgs []string
	LogPath   string
}

// State is the supervisor's lifecycle state.
type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateFailed   State = "failed"
)

// Status is a snapshot for the UI and CLI.
type Status struct {
	State     State     `json:"state"`
	PID       int       `json:"pid,omitempty"`
	BaseURL   string    `json:"base_url,omitempty"`
	Model     string    `json:"model_path,omitempty"`
	Started   time.Time `json:"started,omitempty"`
	Restarts  int       `json:"restarts"`
	LastError string    `json:"last_error,omitempty"`
	Command   string    `json:"command,omitempty"`
}

// Supervisor runs llama-server as a child process, waits for it to report
// healthy, and restarts it with capped backoff if it dies. One Supervisor
// serves one Spec; changing the model means a new Supervisor.
type Supervisor struct {
	spec Spec

	mu       sync.Mutex
	cmd      *exec.Cmd
	state    State
	baseURL  string
	port     int
	started  time.Time
	restarts int
	lastErr  string
	stopping bool
	done     chan struct{}
	ready    chan struct{}
	readyOK  bool
}

// New prepares a supervisor; nothing runs until Start.
func New(spec Spec) *Supervisor {
	return &Supervisor{spec: spec, state: StateStopped, ready: make(chan struct{})}
}

// Start launches the server and blocks until it is healthy, the context is
// cancelled, or startup fails. After a successful start the supervisor
// keeps the process alive in the background until Stop or ctx cancellation.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.cmd != nil {
		s.mu.Unlock()
		return errors.New("already started")
	}
	s.state = StateStarting
	s.done = make(chan struct{})
	s.mu.Unlock()

	if err := s.launch(ctx); err != nil {
		s.setFailed(err)
		return err
	}
	go s.loop(ctx)

	select {
	case <-s.ready:
		s.mu.Lock()
		ok := s.readyOK
		le := s.lastErr
		s.mu.Unlock()
		if !ok {
			return fmt.Errorf("llama-server failed to start: %s", le)
		}
		return nil
	case <-ctx.Done():
		s.Stop()
		return ctx.Err()
	}
}

func (s *Supervisor) launch(ctx context.Context) error {
	port := s.spec.Port
	if port == 0 {
		p, err := freePort()
		if err != nil {
			return err
		}
		port = p
	}
	args := []string{
		"-m", s.spec.ModelPath,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"-c", strconv.Itoa(max(s.spec.Context, 1024)),
		"-np", strconv.Itoa(max(s.spec.Slots, 1)),
		"-ngl", strconv.Itoa(s.spec.GPULayers),
		"--cache-reuse", "256",
		"--jinja",
		"--no-webui",
		"--metrics",
	}
	if s.spec.MMProj != "" {
		args = append(args, "--mmproj", s.spec.MMProj)
	}
	if s.spec.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(s.spec.Threads))
	}
	args = append(args, s.spec.ExtraArgs...)

	cmd := exec.Command(s.spec.Server, args...)
	cmd.Dir = filepath.Dir(s.spec.Server)
	cmd.Env = append(os.Environ(), "LLAMA_ARG_HOST=127.0.0.1")
	var logw io.Writer = io.Discard
	if s.spec.LogPath != "" {
		_ = os.MkdirAll(filepath.Dir(s.spec.LogPath), 0o755)
		if f, err := os.OpenFile(s.spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			logw = f
			cmd.Stdout = f
			cmd.Stderr = f
		}
	}
	if logw == io.Discard {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", s.spec.Server, err)
	}
	s.mu.Lock()
	s.cmd = cmd
	s.port = port
	s.baseURL = "http://127.0.0.1:" + strconv.Itoa(port)
	s.started = time.Now()
	s.state = StateStarting
	s.mu.Unlock()
	slog.Info("llama-server starting", "pid", cmd.Process.Pid, "port", port, "model", filepath.Base(s.spec.ModelPath))
	return nil
}

// loop waits for health, then for exit, restarting with backoff.
func (s *Supervisor) loop(ctx context.Context) {
	defer close(s.done)
	backoff := 2 * time.Second
	firstReady := true
	for {
		s.mu.Lock()
		cmd := s.cmd
		base := s.baseURL
		s.mu.Unlock()
		if cmd == nil {
			return
		}
		// exited is closed once the child has been reaped, so every select
		// below can observe it any number of times; exitErr is only read
		// after that.
		exited := make(chan struct{})
		var exitErr error
		go func() { exitErr = cmd.Wait(); close(exited) }()

		healthy := waitHealthy(ctx, base, exited, 5*time.Minute)
		if healthy {
			s.mu.Lock()
			s.state = StateRunning
			s.lastErr = ""
			s.mu.Unlock()
			backoff = 2 * time.Second
			if firstReady {
				s.mu.Lock()
				s.readyOK = true
				s.mu.Unlock()
				close(s.ready)
				firstReady = false
			}
			slog.Info("llama-server healthy", "url", base)
			select {
			case <-exited:
				s.mu.Lock()
				stopping := s.stopping
				s.mu.Unlock()
				if stopping {
					s.setState(StateStopped)
					return
				}
				msg := "exited"
				if exitErr != nil {
					msg = exitErr.Error()
				}
				slog.Warn("llama-server exited unexpectedly, restarting", "err", msg)
				s.mu.Lock()
				s.lastErr = msg
				s.restarts++
				s.state = StateStarting
				s.mu.Unlock()
			case <-ctx.Done():
				s.Stop()
				<-exited
				return
			}
		} else {
			// Startup never became healthy: the process died or hung. Kill
			// it, report, and either give up (first start) or retry.
			_ = cmd.Process.Kill()
			<-exited
			msg := "llama-server did not become healthy (see " + s.spec.LogPath + ")"
			if exitErr != nil {
				msg = "llama-server exited during startup: " + exitErr.Error() + " (see " + s.spec.LogPath + ")"
			}
			if firstReady {
				s.setFailed(errors.New(msg))
				close(s.ready)
				return
			}
			s.mu.Lock()
			s.lastErr = msg
			s.restarts++
			s.mu.Unlock()
		}
		if ctx.Err() != nil {
			s.setState(StateStopped)
			return
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			s.setState(StateStopped)
			return
		}
		backoff = min(backoff*2, time.Minute)
		if err := s.launch(ctx); err != nil {
			s.setFailed(err)
			return
		}
	}
}

func waitHealthy(ctx context.Context, base string, exited <-chan struct{}, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-exited:
			return false
		case <-time.After(500 * time.Millisecond):
		}
		if Healthy(client, base) {
			return true
		}
	}
	return false
}

// Healthy reports whether a llama-server at base answers /health with 200
// (503 while the model is still loading).
func Healthy(client *http.Client, base string) bool {
	resp, err := client.Get(base + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func (s *Supervisor) setFailed(err error) {
	s.mu.Lock()
	s.state = StateFailed
	s.lastErr = err.Error()
	s.cmd = nil
	s.mu.Unlock()
}

func (s *Supervisor) setState(st State) {
	s.mu.Lock()
	s.state = st
	s.cmd = nil
	s.mu.Unlock()
}

// Stop terminates the child and waits for the loop to finish.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	s.stopping = true
	cmd := s.cmd
	done := s.done
	s.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = terminate(cmd.Process)
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}
	s.setState(StateStopped)
}

// BaseURL is the server's OpenAI-compatible base URL (empty until started).
func (s *Supervisor) BaseURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseURL
}

// Status snapshots the supervisor.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		State:     s.state,
		BaseURL:   s.baseURL,
		Model:     s.spec.ModelPath,
		Started:   s.started,
		Restarts:  s.restarts,
		LastError: s.lastErr,
	}
	if s.cmd != nil && s.cmd.Process != nil {
		st.PID = s.cmd.Process.Pid
		st.Command = s.cmd.String()
	}
	return st
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

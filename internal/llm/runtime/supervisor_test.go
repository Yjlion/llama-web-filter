package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as a fake llama-server when LWF_FAKE_SERVER is set: it
// parses --port, serves /health, and exits on SIGTERM. Supervisor tests
// exec the test binary itself as Spec.Server.
func TestMain(m *testing.M) {
	if os.Getenv("LWF_FAKE_SERVER") == "" {
		os.Exit(m.Run())
	}
	port := "0"
	for i, a := range os.Args {
		if a == "--port" && i+1 < len(os.Args) {
			port = os.Args[i+1]
		}
	}
	if os.Getenv("LWF_FAKE_CRASH") != "" {
		fmt.Fprintln(os.Stderr, "fake server: crashing on purpose")
		os.Exit(3)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		os.Exit(2)
	}
	_ = http.Serve(ln, mux)
}

func TestSupervisorStartsHealthyAndStops(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake server relies on SIGTERM")
	}
	exe, _ := os.Executable()
	t.Setenv("LWF_FAKE_SERVER", "1")
	logPath := filepath.Join(t.TempDir(), "s.log")
	sup := New(Spec{Server: exe, ModelPath: "m.gguf", LogPath: logPath, Slots: 1, Context: 1024})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st := sup.Status()
	if st.State != StateRunning || st.PID == 0 || !strings.HasPrefix(st.BaseURL, "http://127.0.0.1:") {
		t.Fatalf("status = %+v", st)
	}
	if !Healthy(&http.Client{Timeout: time.Second}, st.BaseURL) {
		t.Fatal("server should answer /health")
	}
	sup.Stop()
	if got := sup.Status().State; got != StateStopped {
		t.Fatalf("state after Stop = %s", got)
	}
	if Healthy(&http.Client{Timeout: 300 * time.Millisecond}, st.BaseURL) {
		t.Fatal("server still answering after Stop")
	}
}

func TestSupervisorReportsStartupFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake server relies on SIGTERM")
	}
	exe, _ := os.Executable()
	t.Setenv("LWF_FAKE_SERVER", "1")
	t.Setenv("LWF_FAKE_CRASH", "1")
	sup := New(Spec{Server: exe, ModelPath: "m.gguf", LogPath: filepath.Join(t.TempDir(), "s.log")})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := sup.Start(ctx)
	if err == nil {
		t.Fatal("Start should fail when the server exits before becoming healthy")
	}
	if sup.Status().State != StateFailed {
		t.Fatalf("state = %s, want failed", sup.Status().State)
	}
}

func TestSupervisorMissingBinary(t *testing.T) {
	sup := New(Spec{Server: filepath.Join(t.TempDir(), "nope"), ModelPath: "m.gguf"})
	if err := sup.Start(context.Background()); err == nil {
		t.Fatal("Start should fail for a missing binary")
	}
	_ = exec.ErrNotFound
}

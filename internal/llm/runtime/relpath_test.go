package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// copyExe puts a copy of the test binary (which doubles as a fake
// llama-server, see TestMain) at dst.
func copyExe(t *testing.T, dst string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// A relative data dir (the shipped settings.example.json uses ./data/llm)
// yields relative server and model paths; the supervisor runs the server
// from its own directory, so those must not be resolved from there.
func TestSupervisorStartsWithRelativePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake server relies on SIGTERM")
	}
	root := t.TempDir()
	rel := filepath.Join("data", "llm", "runtime", "rt", "llama-b1", ServerBinaryName())
	copyExe(t, filepath.Join(root, rel))
	t.Chdir(root)
	t.Setenv("LWF_FAKE_SERVER", "1")

	sup := New(Spec{Server: rel, ModelPath: filepath.Join("data", "llm", "models", "m.gguf"), LogPath: filepath.Join("data", "llm", "s.log"), Slots: 1, Context: 1024})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start with relative paths: %v", err)
	}
	defer sup.Stop()
	if _, err := os.Stat(filepath.Join(root, "data", "llm", "s.log")); err != nil {
		t.Fatalf("log not written where expected: %v", err)
	}
}

// A manifest whose server path no longer resolves (recorded relative to an
// earlier working directory, or the data dir moved) still loads, pointing
// at the binary inside the install dir.
func TestLoadInstalledRelocatesStaleServerPath(t *testing.T) {
	dataDir := t.TempDir()
	dir := InstallDir(dataDir, "b1", AccelCPU)
	server := filepath.Join(dir, "llama-b1", ServerBinaryName())
	if err := os.MkdirAll(filepath.Dir(server), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := Installed{Tag: "b1", Accel: AccelCPU, Server: filepath.Join("data", "llm", "elsewhere", ServerBinaryName())}
	data, _ := json.Marshal(m)
	if err := os.WriteFile(manifestPath(dir), data, 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadInstalled(dataDir, "b1", AccelCPU)
	if !ok {
		t.Fatal("LoadInstalled should find the server inside the install dir")
	}
	if got.Server != server {
		t.Fatalf("Server = %q, want %q", got.Server, server)
	}
}

// Cancelling the context (SIGTERM in `webfilter run`) must stop the server
// promptly; the loop used to call Stop on itself and stall for stopGrace.
func TestSupervisorStopsPromptlyOnContextCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake server relies on SIGTERM")
	}
	exe, _ := os.Executable()
	t.Setenv("LWF_FAKE_SERVER", "1")
	sup := New(Spec{Server: exe, ModelPath: "m.gguf", LogPath: filepath.Join(t.TempDir(), "s.log"), Slots: 1, Context: 1024})
	ctx, cancel := context.WithCancel(context.Background())
	startCtx, startCancel := context.WithTimeout(ctx, 20*time.Second)
	defer startCancel()
	if err := sup.Start(startCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	began := time.Now()
	cancel()
	sup.Stop()
	if took := time.Since(began); took > stopGrace/2 {
		t.Fatalf("shutdown took %v, want well under %v", took, stopGrace)
	}
	if st := sup.Status().State; st != StateStopped {
		t.Fatalf("state = %s, want stopped", st)
	}
}

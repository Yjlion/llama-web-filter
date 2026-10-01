package state_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// newRuntime builds a Runtime rooted in a temp dir. Directory settings are
// absolute: the documented defaults are relative and would otherwise resolve
// against the test process's working directory.
func newRuntime(t *testing.T) (*state.Runtime, string) {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "config", "settings.json")

	cfg := models.NewGlobalSettings()
	cfg.CertDir = filepath.Join(dir, "certs")
	cfg.PoliciesDir = filepath.Join(dir, "policies")
	cfg.LogsDir = filepath.Join(dir, "logs")
	cfg.CategoriesDir = filepath.Join(dir, "categories")
	writeSettings(t, settingsPath, cfg)

	if err := os.MkdirAll(cfg.PoliciesDir, 0o755); err != nil {
		t.Fatalf("mkdir policies: %v", err)
	}
	rt, err := state.New(settingsPath)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	t.Cleanup(func() { rt.Logs.Close() })
	return rt, settingsPath
}

func writeSettings(t *testing.T, path string, cfg models.GlobalSettings) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
}

func TestApplySettingsMovesHotFields(t *testing.T) {
	rt, _ := newRuntime(t)

	next := *rt.Settings()
	next.UILanguage = "de"
	next.ProxyAuthEnabled = true
	next.ProxyAuthUsername = "alice"

	pending := rt.ApplySettings(next)
	if len(pending) != 0 {
		t.Errorf("restart-required = %v, want none for an all-hot change", pending)
	}
	got := rt.Settings()
	if got.UILanguage != "de" {
		t.Errorf("ui_language = %q, want %q", got.UILanguage, "de")
	}
	if !got.ProxyAuthEnabled || got.ProxyAuthUsername != "alice" {
		t.Errorf("proxy auth did not apply: %+v", got)
	}
}

// The live snapshot must never advertise a port or listener set that is not
// actually bound - management_access builds its redirect from exactly this.
func TestApplySettingsKeepsRestartRequiredFields(t *testing.T) {
	rt, _ := newRuntime(t)
	originalPort := rt.Settings().MgmtPort
	originalListen := append([]string{}, rt.Settings().ProxyListen...)

	next := *rt.Settings()
	next.MgmtPort = 9999
	next.ProxyListen = []string{"0.0.0.0:9090"}
	next.UILanguage = "fr"

	pending := rt.ApplySettings(next)
	if len(pending) != 2 {
		t.Errorf("restart-required = %v, want mgmt_port and proxy_listen", pending)
	}

	got := rt.Settings()
	if got.MgmtPort != originalPort {
		t.Errorf("mgmt_port = %d, want %d (nothing is bound to the new port)", got.MgmtPort, originalPort)
	}
	if len(got.ProxyListen) != len(originalListen) || got.ProxyListen[0] != originalListen[0] {
		t.Errorf("proxy_listen = %v, want %v", got.ProxyListen, originalListen)
	}
	if got.UILanguage != "fr" {
		t.Errorf("ui_language = %q, want the hot change to still apply", got.UILanguage)
	}
}

func TestReloadSettingsReadsFromDisk(t *testing.T) {
	rt, settingsPath := newRuntime(t)

	next := *rt.Settings()
	next.UILanguage = "es"
	writeSettings(t, settingsPath, next)

	rt.ReloadSettings()
	if got := rt.Settings().UILanguage; got != "es" {
		t.Errorf("ui_language = %q, want %q after ReloadSettings", got, "es")
	}
}

// A corrupt settings.json must leave the running configuration alone rather
// than resetting it to defaults - a half-saved file should not unfilter the
// network.
func TestReloadSettingsKeepsCurrentOnParseError(t *testing.T) {
	rt, settingsPath := newRuntime(t)

	next := *rt.Settings()
	next.UILanguage = "it"
	rt.ApplySettings(next)

	if err := os.WriteFile(settingsPath, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatalf("write corrupt settings: %v", err)
	}
	rt.ReloadSettings()

	if got := rt.Settings().UILanguage; got != "it" {
		t.Errorf("ui_language = %q, want %q kept after a failed reload", got, "it")
	}
}

// Readers take the snapshot pointer on every request while the reload path
// swaps it. Run with -race; this is what justifies the atomic.Pointer.
func TestSettingsSwapIsRaceFree(t *testing.T) {
	rt, _ := newRuntime(t)

	stop := make(chan struct{})
	var readers sync.WaitGroup

	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := rt.Settings()
				_ = s.UILanguage
				_ = s.ProxyAuthEnabled
				_ = s.Icap.PreviewSize
				_ = len(s.ProxyListen)
			}
		}()
	}

	// The writer bounds the test; the readers spin until told to stop. They
	// are waited on separately, because a single WaitGroup covering both
	// would deadlock - the readers only exit once stop is closed, and stop
	// only closes after the wait returns.
	langs := []string{"en", "de", "fr", "es"}
	for i := 0; i < 500; i++ {
		next := *rt.Settings()
		next.UILanguage = langs[i%len(langs)]
		next.ProxyAuthEnabled = i%2 == 0
		rt.ApplySettings(next)
	}

	close(stop)
	readers.Wait()
}

// The watcher must survive settings.json being replaced by rename, which is
// how config.atomicWriteFile writes it - a watch on the file itself would go
// deaf after the first save.
func TestSettingsWatcherSurvivesAtomicRename(t *testing.T) {
	rt, settingsPath := newRuntime(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.Start(ctx)

	for i, lang := range []string{"de", "fr", "es"} {
		next := *rt.Settings()
		next.UILanguage = lang
		atomicWrite(t, settingsPath, next)

		if !waitFor(2*time.Second, func() bool { return rt.Settings().UILanguage == lang }) {
			t.Fatalf("save %d: ui_language = %q, want %q (watcher stopped seeing renames?)",
				i+1, rt.Settings().UILanguage, lang)
		}
	}
}

// atomicWrite mirrors config.atomicWriteFile: write a temp file beside the
// target, then rename over it.
func atomicWrite(t *testing.T, path string, cfg models.GlobalSettings) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if _, err := tmp.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmp.Close()
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

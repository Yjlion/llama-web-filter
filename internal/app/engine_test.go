package app

import (
	"path/filepath"
	"testing"
)

func TestBuildProxyEngineBootstrapsAndWiresPipeline(t *testing.T) {
	// Absolute temp settings path: config.NewBootstrapSettings roots
	// cert/policies/categories/logs dirs from it (per the repo gotcha about
	// relative defaults resolving against the test CWD).
	settingsPath := filepath.Join(t.TempDir(), "config", "settings.json")

	eng, rt, err := BuildProxyEngine(settingsPath, Classifiers{})
	if err != nil {
		t.Fatalf("BuildProxyEngine() error = %v", err)
	}
	defer rt.Logs.Close()

	if eng.Pipeline == nil {
		t.Fatal("engine has no pipeline")
	}
	if eng.Runtime != rt {
		t.Fatal("engine.Runtime not wired to the returned state.Runtime")
	}
	if eng.Transport == nil {
		t.Fatal("engine has no transport")
	}
}

func TestEnsureLocalHTTPProxyListenerAddsLoopbackWhenMissing(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "config", "settings.json")
	eng, rt, err := BuildProxyEngine(settingsPath, Classifiers{})
	if err != nil {
		t.Fatalf("BuildProxyEngine() error = %v", err)
	}
	defer rt.Logs.Close()

	eng.Settings.ProxyListen = []string{"socks5@127.0.0.1:1080"}
	EnsureLocalHTTPProxyListener(eng)
	found := false
	for _, l := range eng.Settings.ProxyListen {
		if l == "regular@127.0.0.1:8080" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ProxyListen = %v, want a loopback regular listener appended", eng.Settings.ProxyListen)
	}
}

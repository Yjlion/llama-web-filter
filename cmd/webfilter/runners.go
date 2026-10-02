package main

import (
	"context"
	"fmt"

	"github.com/yjlion/llama-web-filter/internal/app"
	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// runProxy starts only the forward-proxy engine (no management server).
func runProxy(ctx context.Context, settingsPath string) error {
	settings, err := config.LoadSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	stack := app.NewLLMStack(ctx, settings.LLM)
	defer stack.Close()
	eng, rt, err := app.BuildProxyEngine(settingsPath, stack.PipelineClassifiers())
	if err != nil {
		return fmt.Errorf("start proxy engine: %w", err)
	}
	defer rt.Logs.Close()
	return runEngine(ctx, eng, rt)
}

// runMgmt starts only the management HTTP server (API + embedded UI).
func runMgmt(ctx context.Context, settingsPath string) error {
	srv, err := mgmtapi.NewServer(settingsPath)
	if err != nil {
		return fmt.Errorf("start management server: %w", err)
	}
	defer srv.Logs.Close()
	return app.ServeMgmt(ctx, srv)
}

// runProxyAndMgmt is `webfilter run`: starts the proxy engine and the
// management server as two goroutines in one process, sharing nothing but
// the filesystem except for in-process wire-ups: a CA re-import via the
// management API clears the proxy's leaf-certificate cache immediately
// (mgmtapi.Server.OnCARotated), and a settings save reaches the engine
// directly. If either component fails, the other is cancelled too so `run`
// doesn't limp along half-up. Takes a bare context (rather than a
// *cobra.Command) so the Windows service handler can drive it directly,
// cancelling ctx when the SCM delivers a stop/shutdown control.
func runProxyAndMgmt(ctx context.Context, settingsPath string) error {
	mgmtSrv, err := mgmtapi.NewServer(settingsPath)
	if err != nil {
		return fmt.Errorf("start management server: %w", err)
	}
	return runProxyAndMgmtWith(ctx, settingsPath, mgmtSrv)
}

// runProxyAndMgmtWith is runProxyAndMgmt with a caller-constructed
// management server. Takes ownership of mgmtSrv, including closing its log
// store.
func runProxyAndMgmtWith(ctx context.Context, settingsPath string, mgmtSrv *mgmtapi.Server) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The LLM service comes up first (or reports why it cannot) so the
	// pipeline's classifiers have a backend from the first request.
	stack := app.NewLLMStack(ctx, mgmtSrv.Settings().LLM)
	defer stack.Close()
	mgmtSrv.Scanner = stack.Scanner()
	mgmtSrv.LLM = stack.Controller()
	mgmtSrv.Decisions = stack.Decisions()
	mgmtSrv.LLMClient = stack.Svc.Client

	eng, rt, err := app.BuildProxyEngine(settingsPath, stack.PipelineClassifiers())
	if err != nil {
		mgmtSrv.Logs.Close()
		return fmt.Errorf("start proxy engine: %w", err)
	}
	defer rt.Logs.Close()

	defer mgmtSrv.Logs.Close()
	mgmtSrv.AdBlock = &app.AdBlockAdapter{Runtime: rt}
	mgmtSrv.Sites = rt.SiteCategorizer()
	mgmtSrv.OnCARotated = rt.LeafIssuer.Clear
	// Both components share this process, so a settings save can reach the
	// engine directly rather than waiting on the file watcher. The watcher
	// still runs - it is what covers the split-process deployment - but this
	// makes `run` deterministic and instant.
	mgmtSrv.OnSettingsSaved = func(s models.GlobalSettings) { rt.ApplySettings(s) }

	errCh := make(chan error, 2)
	go func() { errCh <- runEngine(ctx, eng, rt) }()
	go func() { errCh <- app.ServeMgmt(ctx, mgmtSrv) }()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

// runEngine binds the configured proxy listeners and serves until ctx is
// cancelled.
func runEngine(ctx context.Context, eng *proxy.Engine, rt *state.Runtime) error {
	listeners, err := eng.Listen()
	if err != nil {
		return err
	}
	if rt != nil {
		rt.Start(ctx)
	}
	return eng.Serve(ctx, listeners)
}

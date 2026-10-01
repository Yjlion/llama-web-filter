// Package app single-sources the wiring of a runnable webfilter engine so
// every front-end constructs the exact same addon pipeline. The
// registration order below is load-bearing — do not fork it per platform.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/certs"
	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy"
	"github.com/yjlion/llama-web-filter/internal/proxy/addons"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// BuildProxyEngine wires a state.Runtime and the full addon pipeline into
// a ready-to-run proxy.Engine, in the exact registration order
// proxy/main.py uses in the Python original: management access and proxy
// auth gate management/API traffic first, then policy routing and MITM
// control, then the request-side filters (URL, DOH, safesearch), then the
// response-side filters (QUIC-blocking, YouTube, text/image
// classification), with request logging last so it observes the final
// decision.
// Classifiers carries the content-classification backend the pipeline's
// text and image addons call into, and the optional image prefetcher. A
// nil Classifier means the addons pass content through (keyword-only for
// text). In llama-web-filter it is the verdict service in front of the
// edge LLM rather than embedded statistical models.
type Classifiers struct {
	Classifier addons.ContentClassifier
	Prefetcher addons.ImagePrefetcher
}

func BuildProxyEngine(settingsPath string, cls Classifiers) (*proxy.Engine, *state.Runtime, error) {
	if err := config.BootstrapRuntimeFiles(settingsPath); err != nil {
		return nil, nil, err
	}
	rt, err := state.New(settingsPath)
	if err != nil {
		return nil, nil, err
	}

	authGate := addons.NewProxyAuthGate(rt)
	pipeline := proxy.NewPipeline([]proxy.Addon{
		addons.ManagementAccess{},
		authGate,
		addons.PolicyRouter{},
		addons.RuleEvaluator{},
		addons.MitmControl{},
		addons.UrlFilter{},
		addons.AdBlocker{Classifier: cls.Classifier},
		addons.QuicBlocker{},
		addons.DohFilter{},
		addons.SafeSearch{},
		addons.YouTubeFilter{},
		addons.TextClassifier{Classifier: cls.Classifier, Prefetcher: cls.Prefetcher},
		addons.ImageClassifier{Classifier: cls.Classifier},
		addons.RequestLogger{},
	})

	eng := &proxy.Engine{
		SettingsPath: settingsPath,
		Settings:     *rt.Settings(),
		Runtime:      rt,
		Pipeline:     pipeline,
		Transport:    proxy.NewTransport(),
	}
	return eng, rt, nil
}

// EnsureLocalHTTPProxyListener appends a loopback HTTP ("regular") proxy
// listener when none is configured, so a PAC file has an HTTP proxy to
// point at. The 8080 fallback deliberately matches
// GlobalSettings.PrimaryRegularProxyPort, keeping the advertised PAC port
// and the bound listener in agreement. Session-only: the injected entry is
// never persisted to settings.json.
func EnsureLocalHTTPProxyListener(eng *proxy.Engine) {
	if eng == nil {
		return
	}
	for _, entry := range eng.Settings.ProxyListen {
		if spec := models.ParseListenSpec(entry); spec.Mode == "regular" && !spec.TLS {
			return // PAC advertises this plaintext HTTP listener's port
		}
	}
	eng.Settings.ProxyListen = append(eng.Settings.ProxyListen, "regular@127.0.0.1:8080")
	slog.Info("proxy-only: added local HTTP proxy listener for PAC clients", "addr", "127.0.0.1:8080")
}

// ServeMgmt runs the management server (API + embedded UI) until ctx is
// cancelled, over HTTPS when mgmt_tls is set and plain HTTP otherwise.
func ServeMgmt(ctx context.Context, srv *mgmtapi.Server) error {
	cfg := srv.Settings()
	addr := net.JoinHostPort(cfg.MgmtHost, strconv.Itoa(cfg.MgmtPort))

	tlsCfg, err := mgmtTLSConfig(srv)
	if err != nil {
		return err
	}
	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}
	slog.Info("management server listening", "addr", addr, "scheme", scheme)

	httpSrv := &http.Server{Addr: addr, Handler: srv.Router(), TLSConfig: tlsCfg}
	go func() {
		<-ctx.Done()
		// Give in-flight requests a moment to finish before dropping them.
		// This used to be an unconditional Close(); with TLS in play a hard
		// close also aborts handshakes in progress.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), mgmtShutdownGrace)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			_ = httpSrv.Close()
		}
	}()

	if tlsCfg != nil {
		// Certificates come from TLSConfig (either a loaded key pair or the
		// CA-minted GetCertificate callback), so both path arguments are
		// empty by design.
		err = httpSrv.ListenAndServeTLS("", "")
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// mgmtShutdownGrace bounds how long a management-server shutdown waits for
// in-flight requests. Short: nothing on this server is long-running except
// log exports, and `run` cancels the proxy engine at the same time.
const mgmtShutdownGrace = 5 * time.Second

// mgmtTLSConfig returns the management server's TLS config, or nil for plain
// HTTP.
//
// Two certificate sources. An explicit mgmt_cert_file/mgmt_key_file pair is
// used as-is - that is the path for a publicly trusted certificate, and it
// is the one that avoids the bootstrapping problem below. Otherwise leaves
// are minted on demand by the runtime CA, exactly as TLS-wrapped proxy
// listeners do (certs.ServerTLSConfig is shared with Engine.proxyTLSConfig).
//
// Worth stating plainly, because it surprises people: with a CA-minted
// certificate, GET /api/ca-cert is served over HTTPS signed by the very CA
// the client has not installed yet, so the first fetch warns; and WPAD
// clients will not fetch /proxy.pac from an endpoint they do not trust.
// Install the CA out of band, or use a real certificate, or leave mgmt_tls
// off if PAC distribution over this port matters more.
func mgmtTLSConfig(srv *mgmtapi.Server) (*tls.Config, error) {
	cfg := srv.Settings()
	if !cfg.MgmtTLS || srv.ForcePlaintext {
		return nil, nil
	}

	certFile := strings.TrimSpace(cfg.MgmtCertFile)
	keyFile := strings.TrimSpace(cfg.MgmtKeyFile)
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("management TLS certificate: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
		}, nil
	}

	issuer, err := srv.TLSLeafIssuer()
	if err != nil {
		return nil, fmt.Errorf("management TLS: %w", err)
	}
	return certs.ServerTLSConfig(issuer, "webfilter-mgmt"), nil
}

// MgmtURL renders the base URL the management server is reachable at, so
// callers that hand a URL to a browser or an HTTP client (the tray, the
// native GUI, the Android bridge) agree on the scheme instead of each
// hardcoding "http://".
func MgmtURL(cfg models.GlobalSettings, host string, forcePlaintext bool) string {
	scheme := "http"
	if cfg.MgmtTLS && !forcePlaintext {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(cfg.MgmtPort))
}

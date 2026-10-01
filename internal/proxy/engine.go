// Package proxy implements the forward-proxy listener(s) a client's
// browser/OS proxy setting points at: plain HTTP forwarding, CONNECT
// blind-splice passthrough for MITM-excluded hosts, full TLS interception
// (MITM) for everything else, and a SOCKS5 listener (RFC 1928/1929) that
// tunnels into the same interception path - with every request/response
// run through the ordered addon Pipeline. Deliberately a hand-rolled
// net.Listener + crypto/tls.Config.GetCertificate implementation rather
// than a raw net/http.Server - MITM interception needs to own the
// connection down to the TCP/TLS layer (see HANDOFF.md's architecture
// notes on why elazarl/goproxy wasn't used).
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/yjlion/llama-web-filter/internal/certs"
	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
	"github.com/yjlion/llama-web-filter/internal/proxy/state"
)

// Engine owns the forward-proxy listeners derived from settings.json's
// proxy_listen entries, plus the shared Runtime and addon Pipeline every
// connection is processed through.
type Engine struct {
	SettingsPath string

	// Settings is the *startup* snapshot, used for the decisions that are
	// made once and cannot be revisited without a restart: which listeners
	// to bind, and what the tun2socks/gateway supervisors were configured
	// with. Anything read per request must go through LiveSettings() instead,
	// or a settings hot-reload will not reach it.
	Settings models.GlobalSettings

	// Runtime and Pipeline are nil-safe for Listen()-only use (as in
	// engine_test.go's mode-skipping tests); Serve()/handleConn require
	// both to be set for anything beyond a plain 502 passthrough.
	Runtime  *state.Runtime
	Pipeline *Pipeline
	// Transport fetches every upstream response. Defaulted by NewEngine;
	// exported so tests can inject a custom TLSClientConfig.
	Transport *http.Transport

	// InternalListen holds listener specs the engine owns rather than the
	// user: they are bound alongside proxy_listen but never appear in
	// settings.json, in GET /api/settings, or in the UI's listener editor, and
	// so cannot be edited or removed. Purpose-tagged (see Listener.Purpose) so
	// the caller can find the one it asked for after binding.
	//
	// The tun2socks capture listener uses this: tun2socks requires a SOCKS5
	// endpoint, and letting the user retarget or delete it only ever produced
	// silently broken capture.
	InternalListen []InternalListener

	connSeq atomic.Uint64
}

// InternalListener is an engine-owned listener spec: a proxy_listen-style entry
// plus the purpose it was registered for.
type InternalListener struct {
	Purpose string
	Spec    string
}

// NewEngine loads settings.json once. Runtime/Pipeline must be assigned by
// the caller (see cmd/webfilter/runners.go) before Run/Serve is called.
func NewEngine(settingsPath string) (*Engine, error) {
	s, err := config.LoadSettings(settingsPath)
	if err != nil {
		return nil, err
	}
	return &Engine{SettingsPath: settingsPath, Settings: s, Transport: NewTransport()}, nil
}

// Listener is a bound proxy_listen entry tagged with its base mode and
// whether it is TLS-wrapped, so Serve can dispatch SOCKS4/SOCKS5 connections
// to their respective handshakes and everything else to the HTTP-proxy path,
// terminating TLS first for the wrapped variants. It embeds net.Listener so
// existing call sites (Addr, Close) keep working via promotion.
type Listener struct {
	net.Listener
	Mode string // base protocol: regular, socks4, socks5
	TLS  bool   // accepted connections are TLS-terminated before dispatch
	// Purpose is empty for user-configured proxy_listen entries and set to the
	// registering subsystem's name for engine-owned ones (see
	// Engine.InternalListen).
	Purpose string
}

// FindPurpose returns the bound address of the engine-owned listener
// registered for purpose, or "" if there is none.
func FindPurpose(listeners []Listener, purpose string) string {
	for _, ln := range listeners {
		if ln.Purpose == purpose {
			return ln.Addr().String()
		}
	}
	return ""
}

// servedModes are the base proxy_listen modes this engine actually binds and
// serves. Other modes (dns, tun, local, upstream, reverse, wireguard) are
// recognized by models.ParseListenSpec but not yet implemented here; Listen
// logs a warning and skips them.
//
// "transparent" is served on Linux only: it depends on SO_ORIGINAL_DST, which
// is a netfilter facility with no equivalent elsewhere. Binding it on another
// OS would accept connections it could never route.
var servedModes = map[string]bool{
	"regular":     true,
	"socks4":      true,
	"socks5":      true,
	"transparent": runtime.GOOS == "linux",
	"icap":        true,
}

// LiveSettings returns the hot-reloaded settings snapshot when a runtime is
// attached, falling back to the startup snapshot otherwise (Listen()-only
// use in tests, where Runtime is deliberately nil).
func (e *Engine) LiveSettings() *models.GlobalSettings {
	if e.Runtime != nil {
		if s := e.Runtime.Settings(); s != nil {
			return s
		}
	}
	return &e.Settings
}

// Listen binds a listener for every served-mode proxy_listen entry in
// e.Settings (optionally TLS-wrapped). It logs a warning and skips
// unimplemented modes rather than failing the whole engine over one
// unsupported entry. Split out from Run so tests can discover the actual
// bound port when a settings fixture asks for an ephemeral one (port 0).
func (e *Engine) Listen() ([]Listener, error) {
	var listeners []Listener
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}

	for _, entry := range e.Settings.ProxyListen {
		spec := models.ParseListenSpec(entry)
		if !servedModes[spec.Mode] {
			slog.Warn("proxy_listen mode not yet implemented, skipping", "entry", entry, "mode", spec.Mode)
			continue
		}
		addr := net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("listen %s: %w", addr, err)
		}
		listeners = append(listeners, Listener{Listener: ln, Mode: spec.Mode, TLS: spec.TLS})
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no supported proxy_listen entries configured")
	}

	// Engine-owned listeners bind after the user's, and a failure here is
	// fatal rather than skippable: the subsystem that registered one cannot
	// work without it.
	for _, internal := range e.InternalListen {
		spec := models.ParseListenSpec(internal.Spec)
		if !servedModes[spec.Mode] {
			closeAll()
			return nil, fmt.Errorf("internal listener %q: unsupported mode %q", internal.Purpose, spec.Mode)
		}
		addr := net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("listen %s (%s): %w", addr, internal.Purpose, err)
		}
		slog.Info("bound internal listener", "purpose", internal.Purpose, "addr", ln.Addr().String(), "mode", spec.Mode)
		listeners = append(listeners, Listener{Listener: ln, Mode: spec.Mode, TLS: spec.TLS, Purpose: internal.Purpose})
	}
	return listeners, nil
}

// proxyTLSConfig is the server-side TLS config for TLS-wrapped listeners
// (https@ / tls@ / tls+<base>@). The proxy presents a leaf issued on the fly
// by the runtime CA for the SNI the client sent (falling back to a fixed name
// for SNI-less clients), so a client that already trusts the CA for MITM also
// trusts the proxy endpoint itself.
//
// The implementation is shared with the management server's mgmt_tls mode
// (internal/app.ServeMgmt) so the two cannot drift on the SNI-less rule.
func (e *Engine) proxyTLSConfig() *tls.Config {
	return certs.ServerTLSConfig(e.Runtime.LeafIssuer, "webfilter-proxy")
}

// Serve accepts connections on every listener until ctx is cancelled or
// one of them fails, closing every listener before returning. It takes
// ownership of listeners.
func (e *Engine) Serve(ctx context.Context, listeners []Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(listeners))
	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(ln Listener) {
			defer wg.Done()
			slog.Info("proxy listening", "addr", ln.Addr().String(), "mode", ln.Mode)
			if err := e.acceptLoop(ctx, ln); err != nil {
				errCh <- err
				cancel()
			}
		}(ln)
	}

	go func() {
		<-ctx.Done()
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func (e *Engine) acceptLoop(ctx context.Context, ln Listener) error {
	// A TLS-wrapped listener needs the runtime CA to mint its own endpoint
	// leaf; build the config once and reuse it across accepted connections.
	var tlsCfg *tls.Config
	if ln.TLS {
		if e.Runtime == nil {
			return fmt.Errorf("proxy_listen TLS mode %q on %s requires a runtime CA", ln.Mode, ln.Addr())
		}
		tlsCfg = e.proxyTLSConfig()
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept on %s: %w", ln.Addr(), err)
		}
		connID := e.connSeq.Add(1)
		go e.dispatchConn(conn, connID, ln.Mode, tlsCfg)
	}
}

// dispatchConn terminates TLS (when tlsCfg is non-nil) and then hands the
// connection to the handshake for its base mode. The TLS handshake runs here,
// in the per-connection goroutine, so a slow or failed handshake never blocks
// the accept loop.
func (e *Engine) dispatchConn(conn net.Conn, connID uint64, mode string, tlsCfg *tls.Config) {
	// Counted here rather than in acceptLoop so a connection is only
	// recorded once it is actually being served, and so the active gauge's
	// decrement can be deferred against the same return path that closes it.
	metrics.Connections.Inc(mode)
	metrics.ConnectionsActive.Inc()
	defer metrics.ConnectionsActive.Dec()

	if tlsCfg != nil {
		tc := tls.Server(conn, tlsCfg)
		if err := tc.Handshake(); err != nil {
			_ = tc.Close()
			return
		}
		conn = tc
	}
	switch mode {
	case "socks5":
		e.serveSocksConn(conn, connID)
	case "socks4":
		e.serveSocks4Conn(conn, connID)
	case "transparent":
		e.serveTransparentConn(conn, connID)
	case "icap":
		e.serveICAPConn(conn)
	default:
		e.serveConn(conn, connID)
	}
}

// Run is Listen followed by Serve - the normal production entry point.
func (e *Engine) Run(ctx context.Context) error {
	listeners, err := e.Listen()
	if err != nil {
		return err
	}
	if e.Runtime != nil {
		e.Runtime.Start(ctx)
	}
	return e.Serve(ctx, listeners)
}

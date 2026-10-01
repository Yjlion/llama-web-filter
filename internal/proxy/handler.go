package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yjlion/llama-web-filter/internal/metrics"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// NewTransport builds the http.Transport used to fetch every upstream
// response - both plain-HTTP forward requests and MITM'd inner requests
// (which by the time they reach here are just ordinary absolute-URI
// requests with scheme https). HTTP/2 is deliberately never attempted:
// see HANDOFF.md's documented h2-over-MITM out-of-scope decision (ALPN on
// the client-facing MITM handshake below also only ever advertises
// http/1.1). Each Engine gets its own instance (rather than one shared
// package-level Transport) so tests can inject a custom TLSClientConfig
// (e.g. to trust an httptest.NewTLSServer's certificate) without any
// cross-test/cross-engine leakage.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		// Shared dialer so upstream fetches carry the TUN-capture egress mark
		// (see upstream.go); without it the engine's own traffic is captured
		// and fed straight back to it.
		DialContext:           DialUpstreamContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// hopByHopHeaders are meaningful only between a client and its immediate
// proxy, never end-to-end (RFC 7230 §6.1), and must be stripped in both
// directions before forwarding.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func hostOnlyOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// portOf returns the port of a "host:port" tunnel target, or 0 when it has
// none (every caller of handleTunnel builds one, so 0 means "unknown port",
// which matches no port-specific rule).
func portOf(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// serveConn handles one accepted client TCP connection: CONNECT starts a
// blind-splice or MITM tunnel; anything else is a plain-HTTP forward
// request (with its own keep-alive request loop).
func (e *Engine) serveConn(conn net.Conn, connID uint64) {
	defer conn.Close()
	clientIP := hostOnlyOf(conn.RemoteAddr().String())
	proxySockName := hostOnlyOf(conn.LocalAddr().String())

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		e.handleConnect(conn, reader, req, connID, clientIP, proxySockName)
		return
	}

	e.serveRequestLoop(conn, reader, req, connID, clientIP, proxySockName, "", "")
}

// handleConnect processes one CONNECT request: an auth gate, then hands the
// tunnel off to handleTunnel (blind-splice or MITM). reader is the buffered
// reader the CONNECT request was read from; any bytes the client pipelines
// after it (e.g. a TLS ClientHello) stay buffered there and must not be lost.
func (e *Engine) handleConnect(conn net.Conn, reader *bufio.Reader, req *http.Request, connID uint64, clientIP, proxySockName string) {
	targetHost := req.Host
	if _, _, err := net.SplitHostPort(targetHost); err != nil {
		targetHost = net.JoinHostPort(targetHost, "443")
	}
	hostOnly, _, _ := net.SplitHostPort(targetHost)

	var gate ConnectGate
	if e.Pipeline != nil {
		gate = e.Pipeline.ConnectGateAddon()
	}
	if gate != nil {
		if !gate.AuthorizeConnect(req, connID) {
			write407(conn)
			return
		}
		defer gate.ClientDisconnected(connID)
	}

	// The CONNECT readiness signal is an HTTP status line: "200 Connection
	// Established" on success, a 403 when the connection gate refused the
	// target, or a 5xx error response if the upstream dial failed on the
	// blind-splice path.
	ready := func(dialErr error) error {
		if dialErr != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(dialErr, ErrBlockedByPolicy) {
				status = http.StatusForbidden
			}
			writeErrorResponse(conn, status, "proxy: "+dialErr.Error())
			return dialErr
		}
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	}
	e.handleTunnel(conn, reader, targetHost, hostOnly, connID, clientIP, proxySockName, ready)
}

// tunnelReady signals the client that a tunnel to targetHost is established
// (or failed), using the protocol-appropriate reply: an HTTP status line for
// CONNECT, or a SOCKS5 reply for SOCKS. A non-nil dialErr means the upstream
// dial failed (blind-splice path only) and the callback should emit the
// corresponding failure reply. It returns a non-nil error when the tunnel
// must not proceed (write failure, or a signalled dial failure), in which
// case the caller stops.
type tunnelReady func(dialErr error) error

// handleTunnel is the shared post-handshake tunnel path for both CONNECT and
// SOCKS5, entered once the target host is resolved and the client has been
// authenticated. It either blind-splices (MITM-excluded hosts, DoT, or no
// runtime) or performs interception: after signalling readiness it sniffs the
// first client byte to distinguish a TLS ClientHello (0x16) - decrypted via a
// leaf issued by the runtime CA and filtered as https - from plaintext HTTP,
// which is filtered directly as http. reader must be the buffered reader
// wrapping conn, so bytes already read during the handshake (or peeked here)
// aren't lost. ready sends the protocol-specific readiness reply.
//
// Everything it splices first goes through the connection-level gate: a
// spliced connection is invisible to every addon, so the host-only rules in
// hostgate.go are the only filtering it can ever get, and DNS-over-TLS is
// refused outright when the policy filters DNS.
func (e *Engine) handleTunnel(conn net.Conn, reader *bufio.Reader, targetHost, hostOnly string, connID uint64, clientIP, proxySockName string, ready tunnelReady) {
	port := portOf(targetHost)

	// Resolved lazily and once: only the gate below needs it, and the
	// interception path re-resolves it per request through PolicyRouter
	// anyway, so an ordinary MITM'd tunnel pays nothing for this.
	var policy *models.Policy
	policyResolved := false
	clientPolicy := func() *models.Policy {
		if !policyResolved {
			policyResolved = true
			if e.Runtime != nil {
				policy = e.Runtime.GetPolicy(clientIP)
			}
		}
		return policy
	}

	refuse := func(v HostVerdict) {
		e.logConnectionBlock(v, hostOnly, port, clientPolicy(), clientIP)
		_ = ready(blockedError{reason: v.Reason})
	}

	// DNS-over-TLS carries no HTTP, so it must never reach the interception
	// path's http.ReadRequest below - it is spliced instead. When the policy
	// filters DNS, refuse it outright so the client falls back to a resolver
	// the pipeline can see (plain DNS through the UDP relay, or DoH through
	// the doh_filter addon); decrypting it instead is not an option, since DoT
	// clients validate against the system trust store, not this proxy's CA.
	isDoT := port == dotPort
	if isDoT {
		if p := clientPolicy(); p != nil && p.Doh.Enabled {
			refuse(HostVerdict{
				Blocked:   true,
				Reason:    "DNS-over-TLS blocked so DNS filtering applies (port 853)",
				Component: "doh",
			})
			return
		}
	}

	if isDoT || e.Runtime == nil || e.Runtime.ShouldBypassMitm(hostOnly) {
		// Host-level filtering is the only filtering a spliced connection can
		// get: no addon runs on it. MITM'd hosts are deliberately left to the
		// UrlFilter addon, which sees the full URL and can serve the block page.
		if v := HostFilterVerdict(e.Runtime, clientPolicy(), hostOnly); v.Blocked {
			refuse(v)
			return
		}
		blindSplice(conn, targetHost, ready)
		return
	}

	if err := ready(nil); err != nil {
		return
	}

	// Peek the first byte to choose interception mode. A TLS record begins
	// with the handshake content type 0x16; anything else on a proxy tunnel
	// is plaintext HTTP (SOCKS5 clients tunnel port-80 traffic this way -
	// CONNECT is TLS in practice, but the same sniff handles it correctly).
	b, err := reader.Peek(1)
	if err != nil {
		return
	}
	src := bufConn{r: reader, Conn: conn}

	if b[0] == 0x16 {
		tlsConn := tls.Server(src, &tls.Config{
			// Fall back to the tunnel target when the ClientHello carries no
			// SNI - true for IP-literal HTTPS targets, since crypto/tls (like
			// every TLS client) never sends SNI for a literal IP address per
			// RFC 6066. LeafIssuer.GetCertificate alone would reject those.
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := hello.ServerName
				if name == "" {
					name = hostOnly
				}
				return e.Runtime.LeafIssuer.CertificateFor(name)
			},
			NextProtos: []string{"http/1.1"},
		})
		defer tlsConn.Close()

		tr := bufio.NewReader(tlsConn)
		first, err := http.ReadRequest(tr)
		if err != nil {
			return
		}
		e.serveRequestLoop(tlsConn, tr, first, connID, clientIP, proxySockName, targetHost, "https")
		return
	}

	first, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	e.serveRequestLoop(src, reader, first, connID, clientIP, proxySockName, targetHost, "http")
}

// bufConn is a net.Conn that reads through a bufio.Reader - so bytes already
// buffered during the handshake or first-byte sniff aren't lost - while
// delegating writes, deadlines, and address methods to the underlying conn.
type bufConn struct {
	r *bufio.Reader
	net.Conn
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// blindSplice dials targetHost and copies bytes in both directions
// without decrypting anything - used for MITM-excluded hosts. It signals the
// client via ready (success once dialed, failure if the dial fails) and
// blocks until the tunnel closes so the caller's connection cleanup doesn't
// race the copy goroutines.
func blindSplice(conn net.Conn, targetHost string, ready tunnelReady) {
	destConn, err := DialUpstreamTimeout("tcp", targetHost, upstreamTimeout)
	if err != nil {
		_ = ready(err)
		return
	}
	defer destConn.Close()
	if err := ready(nil); err != nil {
		return
	}
	spliceConns(conn, destConn)
}

// spliceConns copies bytes bidirectionally between a and b until either side
// closes, then waits for both directions to finish.
func spliceConns(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		b.Close()
		close(done)
	}()
	io.Copy(a, b)
	a.Close()
	<-done
}

// serveRequestLoop handles first (already read) and every subsequent
// keep-alive request on the same connection, in HTTP/1.1 request/response
// order. tunnelHost/tunnelScheme are set only for MITM'd connections: the
// tunnel target (e.g. "example.com:443") and the scheme to reconstruct
// origin-form request URLs with ("https" for TLS, "http" for a plaintext
// SOCKS tunnel). Both are empty for plain-HTTP forwarding, where each request
// already carries an absolute-URI request-target.
func (e *Engine) serveRequestLoop(w net.Conn, reader *bufio.Reader, first *http.Request, connID uint64, clientIP, proxySockName, tunnelHost, tunnelScheme string) {
	req := first
	for {
		hijacked := e.handleOneRequest(w, reader, req, connID, clientIP, proxySockName, tunnelHost, tunnelScheme)
		if hijacked || req.Close {
			return
		}
		next, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req = next
	}
}

// handleOneRequest handles a single request read off reader/w and reports
// whether it hijacked the connection (a successful WebSocket upgrade,
// spliced raw from this point on) - the caller must stop its keep-alive
// loop in that case, the same way it already does for req.Close.
func (e *Engine) handleOneRequest(w net.Conn, reader *bufio.Reader, req *http.Request, connID uint64, clientIP, proxySockName, tunnelHost, tunnelScheme string) (hijacked bool) {
	if tunnelScheme != "" {
		req.URL.Scheme = tunnelScheme
		if req.URL.Host == "" {
			host := req.Host
			if host == "" {
				host = tunnelHost
			}
			req.URL.Host = host
		}
	} else if !req.URL.IsAbs() {
		writeErrorResponse(w, http.StatusBadRequest, "proxy: request-target must be an absolute URI")
		return
	}
	req.RequestURI = ""

	fc := &FlowContext{
		Runtime:       e.Runtime,
		ClientIP:      clientIP,
		ClientConnID:  connID,
		ProxySockName: proxySockName,
		Request:       req,
	}

	if e.Pipeline != nil {
		e.Pipeline.RunRequest(fc)
	}

	if fc.Response == nil && isWebSocketUpgrade(req) {
		e.tunnelWebSocket(w, reader, req)
		return true
	}

	if fc.Response == nil {
		for _, h := range hopByHopHeaders {
			req.Header.Del(h)
		}
		// Drop the client's Accept-Encoding (browsers advertise
		// "gzip, deflate, br, zstd") so the stdlib Transport negotiates
		// gzip itself and transparently decompresses the response:
		// content-inspecting addons (text_classifier, image_classifier's
		// inline data-URI scan, youtube_filter) must see decoded bytes,
		// and the stdlib can't decode br/zstd. The upstream leg stays
		// compressed on the wire; the client receives an identity body
		// with Content-Length recomputed by writeFlowResponse. The
		// Transport skips its auto-gzip for HEAD and Range requests,
		// which is the correct behavior for those too.
		req.Header.Del("Accept-Encoding")
		resp, err := e.Transport.RoundTrip(req)
		if err != nil {
			// A failure to reach the origin, not a filtering decision: DNS,
			// refused connection, TLS or timeout. Kept as its own counter so
			// "the proxy cannot reach the internet" is distinguishable from
			// "the proxy is blocking things".
			metrics.UpstreamErrors.Inc()
			if e.Pipeline != nil {
				e.Pipeline.RunError(fc)
			}
			writeErrorResponse(w, http.StatusBadGateway, "proxy: "+err.Error())
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fc.Response = resp
		fc.ResponseBody = body
	}

	if e.Pipeline != nil {
		e.Pipeline.RunResponse(fc)
	}

	writeFlowResponse(w, fc)
	return false
}

// isWebSocketUpgrade reports whether req is an HTTP/1.1 WebSocket upgrade
// handshake (RFC 6455 §4.1: Connection: Upgrade + Upgrade: websocket).
func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		headerTokenPresent(req.Header.Get("Connection"), "upgrade")
}

// headerTokenPresent checks a comma-separated header value (e.g.
// "keep-alive, Upgrade") for a case-insensitive token match.
func headerTokenPresent(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// tunnelWebSocket handles a WebSocket upgrade request. http.Transport's
// RoundTrip cannot represent a protocol switch (it always expects a normal
// HTTP response), so this dials the target directly, replays the original
// request verbatim (including the Connection/Upgrade headers regular
// forwarding strips), and - on a 101 response - splices raw bytes
// bidirectionally between client and origin for the rest of the
// connection's life, the same passthrough tradeoff as the CONNECT blind
// splice for MITM-excluded hosts: WS frames are opaque to every addon from
// this point on.
func (e *Engine) tunnelWebSocket(w net.Conn, reader *bufio.Reader, req *http.Request) {
	addr := req.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if req.URL.Scheme == "https" {
			addr = net.JoinHostPort(addr, "443")
		} else {
			addr = net.JoinHostPort(addr, "80")
		}
	}

	var upstream net.Conn
	var err error
	if req.URL.Scheme == "https" {
		tlsCfg := &tls.Config{ServerName: req.URL.Hostname()}
		if e.Transport != nil && e.Transport.TLSClientConfig != nil {
			tlsCfg = e.Transport.TLSClientConfig.Clone()
			tlsCfg.ServerName = req.URL.Hostname()
		}
		upstream, err = tls.DialWithDialer(UpstreamDialer(upstreamTimeout), "tcp", addr, tlsCfg)
	} else {
		upstream, err = DialUpstreamTimeout("tcp", addr, upstreamTimeout)
	}
	if err != nil {
		writeErrorResponse(w, http.StatusBadGateway, "proxy: "+err.Error())
		return
	}
	defer upstream.Close()

	if err := req.Write(upstream); err != nil {
		return
	}

	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		writeErrorResponse(w, http.StatusBadGateway, "proxy: "+err.Error())
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Write(w)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return
	}
	if err := resp.Write(w); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		io.Copy(upstream, reader)
		upstream.Close()
		close(done)
	}()
	io.Copy(w, upstreamReader)
	w.Close()
	<-done
}

func write407(conn net.Conn) {
	body := "Proxy Authentication Required"
	fmt.Fprintf(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
		"Proxy-Authenticate: Basic realm=\"WebFilter Proxy\"\r\n"+
		"Content-Type: text/plain\r\n"+
		"Proxy-Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(body), body)
}

func writeErrorResponse(w io.Writer, status int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/plain\r\n"+
		"Connection: close\r\n"+
		"Content-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(msg), msg)
}

func writeFlowResponse(w io.Writer, fc *FlowContext) {
	resp := fc.Response
	if resp == nil {
		writeErrorResponse(w, http.StatusBadGateway, "proxy: no response")
		return
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	for _, h := range hopByHopHeaders {
		resp.Header.Del(h)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(fc.ResponseBody)))

	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	resp.Header.Write(w)
	io.WriteString(w, "\r\n")
	w.Write(fc.ResponseBody)
}

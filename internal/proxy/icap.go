package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/yjlion/llama-web-filter/internal/icap"
	"github.com/yjlion/llama-web-filter/internal/models"
)

// serveICAPConn serves one ICAP client connection (RFC 3507), letting an
// existing proxy - Squid, in practice - hand its traffic to this filter
// instead of being replaced by it.
//
// Unlike every other front-end this one terminates no client connection and
// splices nothing: it is purely another source of FlowContexts, feeding the
// same ordered addon pipeline that handleOneRequest feeds. The peer on the
// other end is the proxy, not the user, which is why the whole design turns
// on the X-Client-IP header (see icapService.clientIP).
func (e *Engine) serveICAPConn(conn net.Conn) {
	// Read live: icap.* is classified hot, so an operator changing the
	// preview size or body cap does not have to restart.
	cfg := e.LiveSettings().Icap
	srv := &icap.Server{
		Handler:      &icapService{eng: e, cfg: cfg},
		ISTag:        e.icapISTag,
		PreviewSize:  cfg.PreviewSize,
		MaxBodyBytes: cfg.MaxBodyBytes,
	}
	srv.ServeConn(conn)
}

// icapService bridges ICAP transactions to the addon pipeline.
type icapService struct {
	eng *Engine
	cfg models.IcapConfig
}

// icapTxn is the per-transaction state carried from Preview to Modify, so the
// request phase runs exactly once however many times the handler is called.
type icapTxn struct {
	fc *FlowContext
	// requestModified records that a request-phase addon rewrote the request
	// and the client must be handed the new one.
	requestModified bool
	// blocked records that the *request phase* produced a response of its
	// own, which the proxy must serve instead of contacting the origin.
	//
	// This is deliberately not inferred from fc.Response being non-nil.
	// RESPMOD parks the upstream response there too, and a previewed
	// transaction reaches this handler twice - so reading fc.Response as "the
	// request was blocked" would turn every previewed response into a block
	// carrying an empty body on the second pass.
	blocked bool
	// finished guards the response phase, which both logs the flow and must
	// therefore run at most once.
	finished bool
}

// icapISTag is the service tag stamped on every ICAP response. ICAP clients
// cache adapted objects against it, so it must change whenever the filtering
// configuration does - otherwise a policy edit never reaches an object Squid
// already has in its cache.
func (e *Engine) icapISTag() string {
	var gen uint64
	if e.Runtime != nil {
		gen = e.Runtime.Generation()
	}
	return fmt.Sprintf(`"wf-%d"`, gen)
}

// Options advertises the service. Allow204 and a preview are what keep the
// common case cheap: most transactions end without a body ever moving.
func (s *icapService) Options(req *icap.Request) *icap.Options {
	preview := s.cfg.PreviewSize
	if preview <= 0 {
		preview = icap.DefaultPreviewSize
	}
	return &icap.Options{
		Methods:     icap.MethodsForService(req.URI),
		Service:     "WebFilter ICAP",
		Allow204:    true,
		PreviewSize: preview,
		// Preview everything, then decide from the headers whether the rest
		// of the body is worth transferring at all.
		TransferPreview: "*",
		// Bulk formats no addon here can say anything about. Squid skips
		// adaptation for them outright, saving the transfer entirely.
		TransferIgnore: "iso,zip,gz,bz2,xz,7z,rar,exe,msi,dmg,deb,rpm,mp4,mkv,avi,mov,webm,mp3,flac",
		MaxConnections: 256,
		TTL:            600,
	}
}

// Preview decides what it can from the encapsulated headers and the leading
// body bytes, so a body that cannot change the verdict is never transferred.
func (s *icapService) Preview(req *icap.Request) *icap.Response {
	return s.handle(req, req.PreviewComplete)
}

// Modify decides with the complete body in hand.
func (s *icapService) Modify(req *icap.Request) *icap.Response {
	return s.handle(req, true)
}

// handle routes a transaction by method. bodyComplete reports whether
// req.Body is the whole body; when it is not, returning nil asks the client
// for the rest.
func (s *icapService) handle(req *icap.Request, bodyComplete bool) *icap.Response {
	switch req.Method {
	case icap.MethodReqmod:
		return s.reqmod(req, bodyComplete)
	case icap.MethodRespmod:
		return s.respmod(req, bodyComplete)
	}
	return icap.NoContent()
}

// reqmod applies the request phase to a request Squid has not yet forwarded.
//
// Three outcomes: the policy blocks it (a block page goes back instead, and
// the origin is never contacted), an addon rewrote it (SafeSearch), or
// nothing applies and the proxy is told to carry on untouched.
func (s *icapService) reqmod(req *icap.Request, bodyComplete bool) *icap.Response {
	txn := s.requestPhase(req)
	if txn == nil {
		return icap.NoContent()
	}
	if txn.blocked {
		return s.blockResponse(txn)
	}
	if !txn.requestModified {
		return icap.NoContent()
	}
	// The rewritten request has to be handed back in full, body included, so
	// a POST whose body has not arrived yet must wait for it.
	if req.HasBody && !bodyComplete {
		return nil
	}
	return icap.ModifiedRequest(txn.fc.Request, req.Body, req.HasBody)
}

// respmod applies the response phase to a response Squid has fetched.
func (s *icapService) respmod(req *icap.Request, bodyComplete bool) *icap.Response {
	txn := s.requestPhase(req)
	if txn == nil || req.HTTPResponse == nil {
		return icap.NoContent()
	}
	// A URL the policy blocks can still reach RESPMOD - when only the
	// respmod service is configured, or when Squid served the request from
	// cache - so the request-phase verdict is honoured here too.
	if txn.blocked {
		return s.blockResponse(txn)
	}

	fc := txn.fc
	fc.Response = req.HTTPResponse

	// Too big to hold, or an encoding nothing here can read: run the response
	// phase with no body so the flow is still logged and still gets its
	// header-level treatment considered, then wave the object through. The
	// alternative - buffering a multi-gigabyte download to look at it - is
	// how an ICAP server becomes an outage.
	if s.oversize(req) {
		s.finish(txn)
		return icap.NoContent()
	}
	if req.HasBody && !bodyComplete {
		return nil
	}

	decoded, ok := decodeContentEncoding(req.Body, req.HTTPResponse.Header.Get("Content-Encoding"))
	if !ok {
		// Scanning compressed bytes reads as "no match" to every addon, which
		// is a silent filtering failure rather than an honest one. Log it and
		// pass it through instead.
		slog.Debug("icap: response body encoding cannot be decoded, passing unfiltered",
			"encoding", req.HTTPResponse.Header.Get("Content-Encoding"), "url", fc.Request.URL.String())
		s.finish(txn)
		return icap.NoContent()
	}

	originalHeader := req.HTTPResponse.Header.Clone()
	fc.ResponseBody = decoded
	s.finish(txn)

	// A truncated body cannot be handed back faithfully - the tail was never
	// received - so a modification that would rewrite it has to be abandoned.
	// The flow is still logged above.
	if req.BodyTruncated {
		return icap.NoContent()
	}
	if fc.Response == req.HTTPResponse &&
		bytes.Equal(fc.ResponseBody, decoded) &&
		maps.EqualFunc(originalHeader, fc.Response.Header, slices.Equal) {
		return icap.NoContent()
	}

	resp := fc.Response
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	// The body handed back is always identity - it was decoded above and may
	// have been replaced since - so the old coding must not be advertised.
	resp.Header.Del("Content-Encoding")
	return icap.ModifiedResponse(resp, fc.ResponseBody)
}

// blockResponse turns a request-phase block into the ICAP answer that makes
// the proxy serve it: a 200 carrying the encapsulated response, which tells
// the proxy to return this instead of contacting the origin.
func (s *icapService) blockResponse(txn *icapTxn) *icap.Response {
	s.finish(txn)
	resp := txn.fc.Response
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	return icap.ModifiedResponse(resp, txn.fc.ResponseBody)
}

// finish runs the response phase exactly once. RequestLogger lives there, so
// this is also what writes the flow's row in the requests log.
func (s *icapService) finish(txn *icapTxn) {
	if txn.finished {
		return
	}
	txn.finished = true
	if s.eng.Pipeline != nil {
		s.eng.Pipeline.RunResponse(txn.fc)
	}
}

// requestPhase builds the FlowContext for a transaction and runs the request
// phase through it, once per transaction. It returns nil when the transaction
// carries nothing filterable.
func (s *icapService) requestPhase(req *icap.Request) *icapTxn {
	if txn, ok := req.State.(*icapTxn); ok {
		return txn
	}
	httpReq := req.HTTPRequest
	if httpReq == nil {
		// Without the request head there is no URL, so no policy, no category
		// lookup and no log row worth writing. Squid always sends one.
		return nil
	}
	absolutizeICAPURL(httpReq, req)

	fc := &FlowContext{
		Runtime:  s.eng.Runtime,
		ClientIP: s.clientIP(req),
		Frontend: FrontendICAP,
		Request:  httpReq,
	}
	txn := &icapTxn{fc: fc}
	req.State = txn

	// A CONNECT reaching REQMOD is the proxy asking whether to open a tunnel
	// at all. It has no body to inspect and no response to rewrite, so it is
	// answered by the same host-only gate that decides blind-spliced tunnels
	// here - sharing it is what stops the two verdicts drifting apart. This
	// is also the only lever that works on traffic Squid goes on to splice
	// rather than decrypt.
	if httpReq.Method == http.MethodConnect {
		s.gateConnect(txn)
		txn.blocked = fc.Response != nil
		return txn
	}

	// Ask the origin for a coding this filter can actually read. Without it a
	// browser advertising br/zstd gets bodies every content-inspecting addon
	// silently fails to scan - the same reason the engine's own MITM path
	// rewrites this header.
	if s.cfg.NormalizeAcceptEncoding && httpReq.Header.Get("Accept-Encoding") != "" {
		httpReq.Header.Set("Accept-Encoding", "gzip")
		txn.requestModified = true
	}

	if s.eng.Pipeline != nil {
		s.eng.Pipeline.RunRequest(fc)
	}
	txn.blocked = fc.Response != nil
	// SafeSearch is the only request-phase addon that rewrites the request,
	// and it marks every rewrite it makes with wf_action=modified.
	if fc.WFAction == "modified" {
		txn.requestModified = true
	}
	return txn
}

// gateConnect applies the connection-level host gate to a CONNECT that
// arrived through REQMOD, blocking the tunnel before it is opened.
func (s *icapService) gateConnect(txn *icapTxn) {
	fc := txn.fc
	if s.eng.Runtime == nil {
		return
	}
	policy := s.eng.Runtime.GetPolicy(fc.ClientIP)
	fc.Policy = policy
	host := fc.Request.URL.Hostname()
	if host == "" {
		host = hostOnlyOf(fc.Request.Host)
	}
	verdict := HostFilterVerdict(s.eng.Runtime, policy, host)
	if !verdict.Blocked {
		return
	}

	// Give the tunnel target a URL before logging or rendering, so the block
	// reads like every other row instead of the "//example.org:443" a CONNECT
	// request-target parses into.
	if u, err := url.Parse(connectionURL(host, portOf(fc.Request.Host))); err == nil {
		fc.Request.URL = u
	}
	fc.Block(verdict.Reason, verdict.Component)
	// A refused tunnel has no document to replace - the client asked to open
	// a connection, not to fetch a page - so the status has to say no rather
	// than carry a page. The styled body still goes with it: browsers render
	// the response body of a failed CONNECT, so the user sees the same block
	// page they would have got over plain HTTP.
	fc.Response.StatusCode = http.StatusForbidden
}

// clientIP resolves the end user's address for policy selection.
//
// This is the load-bearing detail of the whole ICAP mode: the TCP peer is the
// proxy, so without the header every client in the organisation collapses
// into one address and the per-client policy tiers (MAC/IP/CIDR) silently
// stop working. Squid sends it when configured with "icap_send_client_ip on".
func (s *icapService) clientIP(req *icap.Request) string {
	if s.cfg.TrustClientIPHeader {
		if ip := req.ClientIP(); ip != "" {
			return ip
		}
	}
	return hostOnlyOf(req.RemoteAddr)
}

// oversize reports whether a response declares more body than the service is
// willing to buffer, judged before any of it is transferred.
func (s *icapService) oversize(req *icap.Request) bool {
	max := s.cfg.MaxBodyBytes
	if max <= 0 {
		max = icap.DefaultMaxBodyBytes
	}
	if req.HTTPResponse != nil && req.HTTPResponse.ContentLength > int64(max) {
		return true
	}
	return req.BodyTruncated
}

// absolutizeICAPURL ensures the request URL carries a scheme and host, which
// every host-scoped decision in the pipeline reads.
//
// Squid normally hands over an absolute-form request target, including for
// intercepted traffic, which it reconstructs. Origin-form only shows up from
// other ICAP clients; the scheme is then inferred from the port, since a
// filtered request that arrives as "/search?q=..." would otherwise match no
// policy, no category and no rule at all.
func absolutizeICAPURL(req *http.Request, icapReq *icap.Request) {
	if req.URL == nil {
		req.URL = &url.URL{}
	}
	if req.Method == http.MethodConnect {
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		return
	}
	if req.URL.IsAbs() && req.URL.Host != "" {
		if req.Host == "" {
			req.Host = req.URL.Host
		}
		return
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	req.URL.Host = host
	if req.URL.Scheme == "" {
		req.URL.Scheme = icapRequestScheme(icapReq, host)
	}
	req.Host = host
}

// icapRequestScheme guesses the scheme for an origin-form request: the port
// when there is one, otherwise plain http, which is the only thing a proxy
// can be forwarding in origin form.
func icapRequestScheme(icapReq *icap.Request, host string) string {
	if _, port, err := net.SplitHostPort(host); err == nil && port == "443" {
		return "https"
	}
	if icapReq != nil && strings.HasPrefix(strings.ToLower(icapReq.URI), "icaps://") {
		return "https"
	}
	return "http"
}

// decodeContentEncoding returns body decoded according to encoding, reporting
// false for a coding this build cannot read.
//
// Every content-inspecting addon assumes identity bytes; handing it a
// compressed body does not fail loudly, it just quietly matches nothing. So
// an unknown coding must be reported rather than guessed at - the caller
// passes the object through unfiltered and says so in the log.
func decodeContentEncoding(body []byte, encoding string) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, true
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err != nil {
			return nil, false
		}
		return out, true
	case "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err != nil {
			return nil, false
		}
		return out, true
	}
	return nil, false
}

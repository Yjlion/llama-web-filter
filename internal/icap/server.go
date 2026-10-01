// Package icap implements the server half of ICAP (RFC 3507), the protocol
// proxies use to hand requests and responses to an external adaptation
// service.
//
// It is protocol only: it parses transactions, negotiates preview, and
// serialises answers, but knows nothing about filtering policy. The bridge
// that turns a transaction into a decision lives in internal/proxy, which is
// also the only direction the dependency is allowed to point.
package icap

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults for the server's limits. A caller that leaves a field zero gets
// these.
const (
	DefaultPreviewSize    = 4096
	DefaultMaxBodyBytes   = 8 << 20
	DefaultMaxHeaderBytes = 64 << 10
	DefaultIdleTimeout    = 2 * time.Minute
	DefaultWriteTimeout   = 30 * time.Second
)

// Handler answers ICAP transactions. One connection carries many of them,
// from many different end users, so implementations must be safe for
// concurrent use and must not keep per-connection state.
type Handler interface {
	// Options answers an OPTIONS request. The service URI is req.URI; a
	// server typically derives the advertised Methods from it.
	Options(req *Request) *Options

	// Preview is called once the encapsulated headers and the preview body
	// bytes (if any) have been read. Returning a non-nil Response ends the
	// transaction immediately, without the rest of the body ever being
	// transferred - which is how a body too large or too opaque to inspect
	// is waved through cheaply. Returning nil asks for the whole body.
	//
	// When req.PreviewComplete is set, req.Body is already the entire body
	// and no continuation will happen whatever this returns.
	Preview(req *Request) *Response

	// Modify is called with the complete body and returns the final answer.
	Modify(req *Request) *Response
}

// Options is the advertisement returned for an OPTIONS request.
type Options struct {
	Methods          []string
	Service          string
	PreviewSize      int
	Allow204         bool
	TransferPreview  string
	TransferIgnore   string
	TransferComplete string
	MaxConnections   int
	TTL              int
}

// Server serves ICAP transactions for one Handler.
type Server struct {
	Handler Handler

	// ISTag returns the service tag stamped on every response. ICAP clients
	// cache adapted objects against it, so it must change whenever the
	// filtering configuration does - otherwise a policy edit does not reach
	// anything the proxy already has cached.
	ISTag func() string

	PreviewSize    int
	MaxBodyBytes   int
	MaxHeaderBytes int
	IdleTimeout    time.Duration
	WriteTimeout   time.Duration
}

func (s *Server) previewSize() int {
	if s.PreviewSize > 0 {
		return s.PreviewSize
	}
	return DefaultPreviewSize
}

func (s *Server) maxBodyBytes() int {
	if s.MaxBodyBytes > 0 {
		return s.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

func (s *Server) maxHeaderBytes() int {
	if s.MaxHeaderBytes > 0 {
		return s.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return DefaultIdleTimeout
}

func (s *Server) writeTimeout() time.Duration {
	if s.WriteTimeout > 0 {
		return s.WriteTimeout
	}
	return DefaultWriteTimeout
}

func (s *Server) istag() string {
	if s.ISTag == nil {
		return `"webfilter"`
	}
	tag := s.ISTag()
	if tag == "" {
		return `"webfilter"`
	}
	return tag
}

// ServeConn runs transactions on conn until the peer closes it, it goes idle,
// or a transaction cannot be framed.
//
// ICAP connections are long-lived and heavily reused - Squid opens a pool of
// them and keeps them - so a per-transaction connection teardown would cost
// far more than the filtering itself. A framing error is not recoverable
// (the next transaction's bytes are at an unknown offset), so it closes.
func (s *Server) ServeConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	remote := conn.RemoteAddr().String()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.idleTimeout()))
		req, err := readRequestHead(br, s.maxHeaderBytes())
		if err != nil {
			if !isConnClosed(err) {
				slog.Debug("icap: malformed request", "remote", remote, "err", err)
				_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
				_ = writeResponse(bw, &Response{StatusCode: http.StatusBadRequest}, s.istag())
				_ = bw.Flush()
			}
			return
		}
		req.RemoteAddr = remote

		keepAlive, err := s.serveTransaction(conn, br, bw, req)
		if err != nil {
			if !isConnClosed(err) {
				slog.Debug("icap: transaction failed", "remote", remote, "method", req.Method, "err", err)
			}
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}
		if !keepAlive {
			return
		}
	}
}

// serveTransaction reads whatever body the request carries, consults the
// handler, and writes the answer. It reports whether the connection may
// carry another transaction.
func (s *Server) serveTransaction(conn net.Conn, br *bufio.Reader, bw *bufio.Writer, req *Request) (bool, error) {
	resp, err := s.decide(conn, br, bw, req)
	if err != nil {
		return false, err
	}
	// A 204 the client never offered to accept is a protocol violation; the
	// honest equivalent is handing the message straight back unmodified.
	if resp.StatusCode == http.StatusNoContent && !req.Allow204 && req.Method != MethodOptions {
		resp = echoUnmodified(req)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
	if err := writeResponse(bw, resp, s.istag()); err != nil {
		return false, err
	}
	return !strings.EqualFold(req.Header.Get("Connection"), "close"), nil
}

// decide drives preview negotiation and calls the handler.
func (s *Server) decide(conn net.Conn, br *bufio.Reader, bw *bufio.Writer, req *Request) (*Response, error) {
	if req.Method == MethodOptions {
		return s.optionsResponse(req), nil
	}
	if req.Method != MethodReqmod && req.Method != MethodRespmod {
		return &Response{StatusCode: http.StatusNotImplemented}, nil
	}
	if s.Handler == nil {
		return NoContent(), nil
	}

	if !req.HasBody {
		return s.callModify(req), nil
	}

	if req.PreviewSize >= 0 {
		body, ieof, truncated, err := readChunkedBody(br, s.maxBodyBytes())
		if err != nil {
			return nil, err
		}
		req.Body, req.PreviewComplete, req.BodyTruncated = body, ieof, truncated

		if resp := s.Handler.Preview(req); resp != nil {
			return resp, nil
		}
		if req.PreviewComplete {
			return s.callModify(req), nil
		}

		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout()))
		if err := writeContinue(bw); err != nil {
			return nil, err
		}
		if err := bw.Flush(); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(s.idleTimeout()))
		rest, _, restTruncated, err := readChunkedBody(br, s.maxBodyBytes()-len(req.Body))
		if err != nil {
			return nil, err
		}
		req.Body = append(req.Body, rest...)
		req.BodyTruncated = req.BodyTruncated || restTruncated
		return s.callModify(req), nil
	}

	body, _, truncated, err := readChunkedBody(br, s.maxBodyBytes())
	if err != nil {
		return nil, err
	}
	req.Body, req.BodyTruncated, req.PreviewComplete = body, truncated, true
	return s.callModify(req), nil
}

// callModify invokes the handler's final hook, treating a nil answer as
// "no modification" so a handler bug fails open rather than breaking browsing.
func (s *Server) callModify(req *Request) *Response {
	if resp := s.Handler.Modify(req); resp != nil {
		return resp
	}
	return NoContent()
}

// echoUnmodified hands the encapsulated message back exactly as it arrived,
// for clients that did not offer Allow: 204.
func echoUnmodified(req *Request) *Response {
	switch {
	case req.Method == MethodRespmod && req.HTTPResponse != nil:
		return &Response{StatusCode: http.StatusOK, HTTPResponse: req.HTTPResponse, Body: req.Body, HasBody: req.HasBody}
	case req.HTTPRequest != nil:
		return &Response{StatusCode: http.StatusOK, HTTPRequest: req.HTTPRequest, Body: req.Body, HasBody: req.HasBody}
	}
	return &Response{StatusCode: http.StatusOK}
}

// optionsResponse renders the service advertisement.
func (s *Server) optionsResponse(req *Request) *Response {
	var opts Options
	if s.Handler != nil {
		if o := s.Handler.Options(req); o != nil {
			opts = *o
		}
	}
	if len(opts.Methods) == 0 {
		opts.Methods = MethodsForService(req.URI)
	}
	if opts.PreviewSize <= 0 {
		opts.PreviewSize = s.previewSize()
	}

	header := http.Header{}
	header.Set("Methods", strings.Join(opts.Methods, ", "))
	if opts.Service != "" {
		header.Set("Service", opts.Service)
	}
	if opts.Allow204 {
		header.Set("Allow", "204")
	}
	header.Set("Preview", strconv.Itoa(opts.PreviewSize))
	if opts.TransferPreview != "" {
		header.Set("Transfer-Preview", opts.TransferPreview)
	}
	if opts.TransferIgnore != "" {
		header.Set("Transfer-Ignore", opts.TransferIgnore)
	}
	if opts.TransferComplete != "" {
		header.Set("Transfer-Complete", opts.TransferComplete)
	}
	if opts.MaxConnections > 0 {
		header.Set("Max-Connections", strconv.Itoa(opts.MaxConnections))
	}
	if opts.TTL > 0 {
		header.Set("Options-TTL", strconv.Itoa(opts.TTL))
	}
	return &Response{StatusCode: http.StatusOK, Header: header}
}

// MethodsForService guesses which ICAP method a service URI is for, so one
// server can back both vectoring points without either being configured.
//
// An ICAP client checks the advertised Methods against the method it intends
// to send and refuses the service on a mismatch, so guessing wrong is fatal
// to that service - which is why an unrecognisable path advertises both
// rather than picking one.
func MethodsForService(uri string) []string {
	path := uri
	if i := strings.Index(path, "://"); i >= 0 {
		if j := strings.IndexByte(path[i+3:], '/'); j >= 0 {
			path = path[i+3+j:]
		} else {
			path = "/"
		}
	}
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "resp"):
		return []string{MethodRespmod}
	case strings.Contains(lower, "req"):
		return []string{MethodReqmod}
	}
	return []string{MethodReqmod, MethodRespmod}
}

// isConnClosed reports whether err is the ordinary end of a connection - a
// peer that hung up or an idle timeout - rather than something worth logging.
func isConnClosed(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}

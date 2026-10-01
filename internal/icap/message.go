package icap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// ICAP methods (RFC 3507 §4.3-4.10).
const (
	MethodOptions = "OPTIONS"
	MethodReqmod  = "REQMOD"
	MethodRespmod = "RESPMOD"
)

// Request is one parsed ICAP request: the ICAP envelope plus whichever HTTP
// message parts it encapsulated.
//
// Body is the *decoded* encapsulated body - de-chunked, and for a previewed
// transaction only as much as has been read so far (see PreviewComplete).
// The HTTP message parts never carry their own body: HTTPRequest.Body and
// HTTPResponse.Body are left unusable by design, exactly as the proxy
// pipeline's FlowContext does it, so there is one buffered copy and one
// obvious place to find it.
type Request struct {
	Method string
	URI    string
	Header http.Header

	HTTPRequest  *http.Request
	HTTPResponse *http.Response

	Body []byte
	// HasBody distinguishes "null-body" (no body part at all) from an
	// encapsulated body that happens to be empty.
	HasBody bool
	// BodyTruncated is set when the body ran past the server's limit; the
	// excess was drained off the connection and discarded, so Body is a
	// prefix and must not be inspected as if it were the whole thing.
	BodyTruncated bool

	// PreviewSize is the byte count from the client's Preview header, or -1
	// when it sent none.
	PreviewSize int
	// PreviewComplete reports that the preview's zero chunk carried "ieof":
	// the preview *is* the whole body and asking for more would hang.
	PreviewComplete bool
	// Allow204 reports whether the client offered "Allow: 204". Answering
	// 204 when it did not is a protocol violation, so the server echoes the
	// unmodified message back as a 200 instead.
	Allow204 bool

	// RemoteAddr is the ICAP client's address - the proxy's, not the end
	// user's. For the end user see the X-Client-IP header.
	RemoteAddr string

	// State is an opaque per-transaction slot for the Handler. Preview and
	// Modify are called with the same *Request, so work done to reach a
	// preview verdict (parsing, policy lookup, the request-phase pipeline
	// run) can be carried over instead of repeated - which matters because
	// re-running the pipeline would also re-apply its side effects, such as
	// writing a second block-log row for one page view.
	State any
}

// ClientIP returns the end user's address as reported by the ICAP client,
// or "" when it sent none. Squid populates X-Client-IP when configured with
// "icap_send_client_ip on"; the other spellings are what other ICAP clients
// use for the same thing.
func (r *Request) ClientIP() string {
	for _, h := range []string{"X-Client-IP", "X-Client-Ip", "X-Forwarded-For"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			// X-Forwarded-For may be a list; the original client is first.
			if i := strings.IndexByte(v, ','); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			return v
		}
	}
	return ""
}

// Response is the ICAP server's answer to one transaction: either 204 (no
// modification needed) or 200 carrying a replacement HTTP message.
//
// A REQMOD 200 carrying HTTPResponse rather than HTTPRequest is the
// "respond instead of fetching" case - how a block page reaches the user
// without the origin ever being contacted.
type Response struct {
	StatusCode int
	Header     http.Header

	HTTPRequest  *http.Request
	HTTPResponse *http.Response
	Body         []byte
	// HasBody must be set for an encapsulated message that carries a body,
	// including an empty one; otherwise null-body is advertised.
	HasBody bool
}

// NoContent builds the 204 "leave it alone" response.
func NoContent() *Response {
	return &Response{StatusCode: http.StatusNoContent}
}

// ModifiedRequest builds a REQMOD 200 carrying an adapted request.
func ModifiedRequest(req *http.Request, body []byte, hasBody bool) *Response {
	return &Response{StatusCode: http.StatusOK, HTTPRequest: req, Body: body, HasBody: hasBody}
}

// ModifiedResponse builds a 200 carrying an adapted (or wholly synthesized)
// HTTP response.
func ModifiedResponse(resp *http.Response, body []byte) *Response {
	return &Response{StatusCode: http.StatusOK, HTTPResponse: resp, Body: body, HasBody: true}
}

// statusText maps the ICAP status codes this server emits to their reason
// phrases. ICAP reuses HTTP's codes but not all of HTTP's phrases, so the
// table is explicit rather than deferring to http.StatusText.
var statusText = map[int]string{
	100: "Continue",
	200: "OK",
	204: "No Content",
	400: "Bad Request",
	404: "ICAP Service Not Found",
	405: "Method Not Allowed For Service",
	408: "Request Timeout",
	413: "Request Entity Too Large",
	500: "Server Error",
	501: "Not Implemented",
	503: "Service Overloaded",
}

func reasonPhrase(code int) string {
	if s, ok := statusText[code]; ok {
		return s
	}
	return "Unknown"
}

// readRequestHead parses the ICAP request line, the ICAP headers, and every
// encapsulated *header* part, leaving the body (if any) unread on br so the
// server can drive preview negotiation.
func readRequestHead(br *bufio.Reader, maxHeaderBytes int) (*Request, error) {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return nil, fmt.Errorf("icap: malformed request line %q", line)
	}
	method, uri, version := strings.ToUpper(fields[0]), fields[1], strings.ToUpper(fields[2])
	if !strings.HasPrefix(version, "ICAP/") {
		return nil, fmt.Errorf("icap: unsupported protocol %q", version)
	}

	mime, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req := &Request{
		Method:      method,
		URI:         uri,
		Header:      http.Header(mime),
		PreviewSize: -1,
	}
	if v := req.Header.Get("Preview"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			req.PreviewSize = n
		}
	}
	for _, v := range req.Header.Values("Allow") {
		for _, tok := range strings.Split(v, ",") {
			if strings.TrimSpace(tok) == "204" {
				req.Allow204 = true
			}
		}
	}

	entries, err := parseEncapsulated(req.Header.Get("Encapsulated"))
	if err != nil {
		return nil, err
	}
	if err := readEncapsulatedHeads(br, req, entries, maxHeaderBytes); err != nil {
		return nil, err
	}
	return req, nil
}

// readEncapsulatedHeads consumes the header parts named by entries, in offset
// order, parsing each into the matching field of req. A header part's length
// is the distance to the next part's offset - the Encapsulated header is the
// only length information ICAP gives, which is why the entries must be sorted
// before they are walked.
func readEncapsulatedHeads(br *bufio.Reader, req *Request, entries []encapsulatedEntry, maxHeaderBytes int) error {
	for i, e := range entries {
		if e.isBody() {
			req.HasBody = e.Name != entNullBody
			return nil
		}
		if i+1 >= len(entries) {
			return fmt.Errorf("icap: Encapsulated header part %q has no following part to bound it", e.Name)
		}
		length := entries[i+1].Offset - e.Offset
		if length < 0 || length > maxHeaderBytes {
			return fmt.Errorf("icap: encapsulated %s length %d out of range", e.Name, length)
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		switch e.Name {
		case entReqHdr:
			parsed, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
			if err != nil {
				// Deliberately %v, not %w: a truncated header part reports
				// ErrUnexpectedEOF, and wrapping it would make a malformed
				// message indistinguishable from a peer that hung up - so the
				// server would close silently instead of answering 400.
				return fmt.Errorf("icap: parse encapsulated request: %v", err)
			}
			req.HTTPRequest = parsed
		case entResHdr:
			parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf)), nil)
			if err != nil {
				return fmt.Errorf("icap: parse encapsulated response: %v", err)
			}
			req.HTTPResponse = parsed
		default:
			return fmt.Errorf("icap: unexpected Encapsulated part %q", e.Name)
		}
	}
	return nil
}

// writeResponse serialises resp onto w. istag is stamped on every response
// (RFC 3507 requires it on all but 100 Continue); extra carries the OPTIONS
// headers, which are the only ones that vary per response kind.
func writeResponse(w io.Writer, resp *Response, istag string) error {
	var encap []encapsulatedEntry
	var parts bytes.Buffer

	switch {
	case resp.HTTPRequest != nil:
		encap = append(encap, encapsulatedEntry{Name: entReqHdr, Offset: 0})
		if err := writeHTTPRequestHead(&parts, resp.HTTPRequest, len(resp.Body), resp.HasBody); err != nil {
			return err
		}
		if resp.HasBody {
			encap = append(encap, encapsulatedEntry{Name: entReqBody, Offset: parts.Len()})
		} else {
			encap = append(encap, encapsulatedEntry{Name: entNullBody, Offset: parts.Len()})
		}
	case resp.HTTPResponse != nil:
		encap = append(encap, encapsulatedEntry{Name: entResHdr, Offset: 0})
		if err := writeHTTPResponseHead(&parts, resp.HTTPResponse, len(resp.Body), resp.HasBody); err != nil {
			return err
		}
		if resp.HasBody {
			encap = append(encap, encapsulatedEntry{Name: entResBody, Offset: parts.Len()})
		} else {
			encap = append(encap, encapsulatedEntry{Name: entNullBody, Offset: parts.Len()})
		}
	default:
		encap = append(encap, encapsulatedEntry{Name: entNullBody, Offset: 0})
	}

	var head bytes.Buffer
	fmt.Fprintf(&head, "ICAP/1.0 %d %s\r\n", resp.StatusCode, reasonPhrase(resp.StatusCode))
	if istag != "" {
		fmt.Fprintf(&head, "ISTag: %s\r\n", istag)
	}
	for key, values := range resp.Header {
		for _, v := range values {
			fmt.Fprintf(&head, "%s: %s\r\n", icapHeaderName(key), v)
		}
	}
	fmt.Fprintf(&head, "Encapsulated: %s\r\n\r\n", formatEncapsulated(encap))

	if _, err := w.Write(head.Bytes()); err != nil {
		return err
	}
	if _, err := w.Write(parts.Bytes()); err != nil {
		return err
	}
	if resp.HTTPRequest == nil && resp.HTTPResponse == nil {
		return nil
	}
	if !resp.HasBody {
		return nil
	}
	return writeChunkedBody(w, resp.Body)
}

// icapHeaderNames restores the spellings RFC 3507 uses for headers whose
// canonical HTTP form differs. Header names are case-insensitive, so this is
// cosmetic for a conformant client - but ICAP tooling and packet captures are
// read by people, and "Options-Ttl" in a trace looks like a bug every time.
var icapHeaderNames = map[string]string{
	"Istag":       "ISTag",
	"Options-Ttl": "Options-TTL",
}

// icapHeaderName maps a canonical http.Header key to its ICAP spelling.
func icapHeaderName(key string) string {
	if name, ok := icapHeaderNames[key]; ok {
		return name
	}
	return key
}

// writeContinue emits the interim response that asks a previewing client for
// the rest of the body.
func writeContinue(w io.Writer) error {
	_, err := io.WriteString(w, "ICAP/1.0 100 Continue\r\n\r\n")
	return err
}

// requestTarget renders the request-line target for an adapted request in the
// same form it arrived in. Squid sends absolute-form for forwarded requests
// and reconstructs one for intercepted traffic, but a client that sent
// origin-form must get origin-form back or it will not recognise its own
// request.
func requestTarget(req *http.Request) string {
	if req.URL == nil {
		return req.RequestURI
	}
	if req.Method == http.MethodConnect {
		return req.URL.Host
	}
	if strings.HasPrefix(req.RequestURI, "/") {
		return req.URL.RequestURI()
	}
	return req.URL.String()
}

// writeHTTPRequestHead serialises an HTTP request head (request line, headers,
// blank line) into the encapsulated section.
//
// Content-Length is rewritten from the body the ICAP layer is about to send,
// and Transfer-Encoding is dropped: the encapsulated body is chunked by ICAP
// itself, so a leftover "Transfer-Encoding: chunked" would describe a framing
// the receiver must not apply a second time.
func writeHTTPRequestHead(w io.Writer, req *http.Request, bodyLen int, hasBody bool) error {
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", req.Method, requestTarget(req)); err != nil {
		return err
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		if _, err := fmt.Fprintf(w, "Host: %s\r\n", host); err != nil {
			return err
		}
	}
	header := cloneWithoutFraming(req.Header)
	if hasBody {
		header.Set("Content-Length", strconv.Itoa(bodyLen))
	}
	if err := header.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// writeHTTPResponseHead serialises an HTTP response head into the
// encapsulated section, with the same Content-Length/Transfer-Encoding
// normalisation as writeHTTPRequestHead.
func writeHTTPResponseHead(w io.Writer, resp *http.Response, bodyLen int, hasBody bool) error {
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	reason := resp.Status
	if i := strings.IndexByte(reason, ' '); i >= 0 {
		reason = reason[i+1:]
	}
	if reason == "" {
		reason = http.StatusText(status)
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", status, reason); err != nil {
		return err
	}
	header := cloneWithoutFraming(resp.Header)
	if hasBody {
		header.Set("Content-Length", strconv.Itoa(bodyLen))
	}
	if err := header.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

// cloneWithoutFraming copies h minus the two headers that describe the *old*
// framing of a body the ICAP layer is about to re-frame: its length and its
// chunking.
//
// Content-Encoding is deliberately left alone. Whether a returned body is
// still encoded is a decision only the caller can make - it is the one that
// knows whether it decoded the bytes or is echoing them back untouched - and
// stripping the header from a body that is still gzipped would hand the
// client something it cannot read.
func cloneWithoutFraming(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Transfer-Encoding":
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}

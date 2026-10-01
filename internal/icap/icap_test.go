package icap

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stubHandler lets each test say what the server should answer without
// standing up the whole filtering pipeline.
type stubHandler struct {
	options *Options
	preview func(*Request) *Response
	modify  func(*Request) *Response

	lastModify *Request
}

func (h *stubHandler) Options(*Request) *Options { return h.options }

func (h *stubHandler) Preview(req *Request) *Response {
	if h.preview != nil {
		return h.preview(req)
	}
	return nil
}

func (h *stubHandler) Modify(req *Request) *Response {
	h.lastModify = req
	if h.modify != nil {
		return h.modify(req)
	}
	return NoContent()
}

// serve runs one connection's worth of transactions against h, feeding it
// request and returning everything the server wrote back.
func serve(t *testing.T, h Handler, request string) string {
	t.Helper()
	srv := &Server{Handler: h, ISTag: func() string { return `"test-1"` }}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		srv.ServeConn(server)
		close(done)
	}()

	var out bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		_, _ = out.ReadFrom(client)
		close(readDone)
	}()

	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// The server closes the connection once the peer stops sending, which is
	// what ends both goroutines.
	_ = client.SetWriteDeadline(time.Now().Add(time.Second))
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = client.Close()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return within 5s")
	}
	<-readDone
	return out.String()
}

func TestOptionsAdvertisesServiceCapabilities(t *testing.T) {
	h := &stubHandler{options: &Options{
		Service:     "WebFilter",
		Allow204:    true,
		PreviewSize: 1024,
		TTL:         600,
	}}
	got := serve(t, h, "OPTIONS icap://127.0.0.1/respmod ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: null-body=0\r\n\r\n")

	for _, want := range []string{
		"ICAP/1.0 200 OK",
		"ISTag: \"test-1\"",
		"Methods: RESPMOD",
		"Allow: 204",
		"Preview: 1024",
		"Options-TTL: 600",
		"Encapsulated: null-body=0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("OPTIONS response missing %q, got:\n%s", want, got)
		}
	}
}

// A client that asks about a service whose name says nothing must be told
// both methods: advertising the wrong one makes the client refuse the
// service outright.
func TestMethodsForService(t *testing.T) {
	cases := []struct {
		uri  string
		want []string
	}{
		{"icap://host:1344/respmod", []string{MethodRespmod}},
		{"icap://host:1344/reqmod", []string{MethodReqmod}},
		{"icap://host/webfilter_response", []string{MethodRespmod}},
		{"icap://host/", []string{MethodReqmod, MethodRespmod}},
		{"/avscan", []string{MethodReqmod, MethodRespmod}},
	}
	for _, tc := range cases {
		got := MethodsForService(tc.uri)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("MethodsForService(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestReqmodAllowedReturns204(t *testing.T) {
	h := &stubHandler{}
	reqHdr := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := "REQMOD icap://127.0.0.1/reqmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Allow: 204\r\n" +
		"Encapsulated: req-hdr=0, null-body=" + strconv.Itoa(len(reqHdr)) + "\r\n" +
		"\r\n" +
		reqHdr

	got := serve(t, h, req)

	if !strings.HasPrefix(got, "ICAP/1.0 204 No Content\r\n") {
		t.Errorf("want 204, got:\n%s", got)
	}
	if h.lastModify == nil {
		t.Fatal("handler never saw the transaction")
	}
	if h.lastModify.HTTPRequest.URL.String() != "http://example.com/" {
		t.Errorf("encapsulated URL = %q", h.lastModify.HTTPRequest.URL.String())
	}
	if h.lastModify.HasBody {
		t.Error("null-body request reported HasBody")
	}
}

// Squid always offers Allow: 204, but the RFC does not require it, and
// answering 204 to a client that did not offer it is a protocol violation -
// so the server owes that client the message back verbatim instead.
func TestNoAllow204EchoesMessageBack(t *testing.T) {
	h := &stubHandler{}
	reqHdr := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := "REQMOD icap://127.0.0.1/reqmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Encapsulated: req-hdr=0, null-body=" + strconv.Itoa(len(reqHdr)) + "\r\n" +
		"\r\n" +
		reqHdr

	got := serve(t, h, req)

	if !strings.HasPrefix(got, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("want 200 echo, got:\n%s", got)
	}
	if !strings.Contains(got, "GET http://example.com/ HTTP/1.1") {
		t.Errorf("echo did not carry the original request line, got:\n%s", got)
	}
}

func TestRespmodReplacesBody(t *testing.T) {
	blockPage := []byte("<html>blocked</html>")
	h := &stubHandler{modify: func(req *Request) *Response {
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/html"}},
		}
		return ModifiedResponse(resp, blockPage)
	}}

	resHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\n"
	req := "RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Allow: 204\r\n" +
		"Encapsulated: res-hdr=0, res-body=" + strconv.Itoa(len(resHdr)) + "\r\n" +
		"\r\n" +
		resHdr +
		"5\r\nhello\r\n0\r\n\r\n"

	got := serve(t, h, req)

	if !strings.HasPrefix(got, "ICAP/1.0 200 OK\r\n") {
		t.Fatalf("want 200, got:\n%s", got)
	}
	if !strings.Contains(got, "Content-Length: 20") {
		t.Errorf("replacement body length not restated, got:\n%s", got)
	}
	if !strings.Contains(got, "14\r\n<html>blocked</html>\r\n0\r\n\r\n") {
		t.Errorf("replacement body not chunked back, got:\n%s", got)
	}
	if h.lastModify == nil || string(h.lastModify.Body) != "hello" {
		t.Errorf("handler saw body %q, want \"hello\"", h.lastModify.Body)
	}
}

// The preview handshake is the part a hand-rolled ICAP server most often gets
// wrong: the server must send 100 Continue and then read a *second* chunked
// stream, whose bytes complete the first.
func TestPreviewContinueDeliversWholeBody(t *testing.T) {
	h := &stubHandler{}
	resHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
	head := "RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Allow: 204\r\n" +
		"Preview: 4\r\n" +
		"Encapsulated: res-hdr=0, res-body=" + strconv.Itoa(len(resHdr)) + "\r\n" +
		"\r\n" +
		resHdr +
		"4\r\nabcd\r\n0\r\n\r\n"

	srv := &Server{Handler: h, ISTag: func() string { return `"t"` }}
	client, server := net.Pipe()
	go srv.ServeConn(server)
	defer client.Close()

	if _, err := client.Write([]byte(head)); err != nil {
		t.Fatalf("write preview: %v", err)
	}
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read continue: %v", err)
	}
	if !strings.HasPrefix(line, "ICAP/1.0 100 Continue") {
		t.Fatalf("want 100 Continue, got %q", line)
	}
	if _, err := br.ReadString('\n'); err != nil { // blank line
		t.Fatalf("read continue terminator: %v", err)
	}

	if _, err := client.Write([]byte("3\r\nefg\r\n0\r\n\r\n")); err != nil {
		t.Fatalf("write remainder: %v", err)
	}
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if !strings.HasPrefix(status, "ICAP/1.0 204") {
		t.Errorf("want 204 after continue, got %q", status)
	}
	if h.lastModify == nil || string(h.lastModify.Body) != "abcdefg" {
		t.Errorf("assembled body = %q, want \"abcdefg\"", h.lastModify.Body)
	}
}

// A preview that ends in "ieof" is the whole body. Asking such a client to
// continue would hang the transaction until the idle timeout, so the server
// must go straight to the final decision.
func TestPreviewIEOFSkipsContinue(t *testing.T) {
	h := &stubHandler{}
	resHdr := "HTTP/1.1 200 OK\r\n\r\n"
	req := "RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\n" +
		"Allow: 204\r\nPreview: 100\r\n" +
		"Encapsulated: res-hdr=0, res-body=" + strconv.Itoa(len(resHdr)) + "\r\n\r\n" +
		resHdr +
		"2\r\nhi\r\n0; ieof\r\n\r\n"

	got := serve(t, h, req)

	if strings.Contains(got, "100 Continue") {
		t.Errorf("server asked for more after ieof, got:\n%s", got)
	}
	if h.lastModify == nil || !h.lastModify.PreviewComplete {
		t.Error("PreviewComplete not set for an ieof preview")
	}
	if string(h.lastModify.Body) != "hi" {
		t.Errorf("body = %q, want \"hi\"", h.lastModify.Body)
	}
}

// Deciding on the preview alone is what keeps a multi-gigabyte download from
// being streamed through the filter just to be waved past.
func TestPreviewVerdictEndsTransactionEarly(t *testing.T) {
	h := &stubHandler{preview: func(*Request) *Response { return NoContent() }}
	resHdr := "HTTP/1.1 200 OK\r\n\r\n"
	req := "RESPMOD icap://127.0.0.1/respmod ICAP/1.0\r\n" +
		"Allow: 204\r\nPreview: 4\r\n" +
		"Encapsulated: res-hdr=0, res-body=" + strconv.Itoa(len(resHdr)) + "\r\n\r\n" +
		resHdr +
		"4\r\nabcd\r\n0\r\n\r\n"

	got := serve(t, h, req)

	if strings.Contains(got, "100 Continue") {
		t.Errorf("preview verdict still asked for the body, got:\n%s", got)
	}
	if !strings.Contains(got, "ICAP/1.0 204") {
		t.Errorf("want 204 from the preview verdict, got:\n%s", got)
	}
	if h.lastModify != nil {
		t.Error("Modify ran even though Preview already answered")
	}
}

func TestParseEncapsulatedSortsByOffset(t *testing.T) {
	entries, err := parseEncapsulated("res-body=213, req-hdr=0, res-hdr=137")
	if err != nil {
		t.Fatalf("parseEncapsulated: %v", err)
	}
	want := []encapsulatedEntry{
		{Name: "req-hdr", Offset: 0},
		{Name: "res-hdr", Offset: 137},
		{Name: "res-body", Offset: 213},
	}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("entry %d = %+v, want %+v", i, entries[i], w)
		}
	}
}

func TestReadChunkedBodyLimitDrainsRemainder(t *testing.T) {
	// Two chunks, the second of which pushes past the limit. The limit must
	// bound what is buffered without desynchronising the connection: the
	// bytes after it still have to come off the wire.
	raw := "4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\nNEXT"
	br := bufio.NewReader(strings.NewReader(raw))

	body, ieof, truncated, err := readChunkedBody(br, 6)
	if err != nil {
		t.Fatalf("readChunkedBody: %v", err)
	}
	if string(body) != "abcdef" {
		t.Errorf("body = %q, want \"abcdef\"", body)
	}
	if !truncated {
		t.Error("truncated not reported")
	}
	if ieof {
		t.Error("ieof reported for a plain zero chunk")
	}
	rest, _ := br.ReadString('T')
	if rest != "NEXT" {
		t.Errorf("reader left at %q, want the stream positioned after the body", rest)
	}
}

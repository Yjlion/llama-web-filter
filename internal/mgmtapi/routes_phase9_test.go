package mgmtapi_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yjlion/llama-web-filter/internal/logstore"
	"github.com/yjlion/llama-web-filter/internal/mgmtapi"
)

// doRequest drives the server's router directly with an in-memory recorder,
// avoiding a real socket. Auth is open when no management password is set
// (the default for these tests).
func doRequest(t *testing.T, s *mgmtapi.Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, r)
	return rr
}

// newServerWithCategories builds a Server whose categories_dir points at a
// populated temp directory, so /api/categories has real data to return.
func newServerWithCategories(t *testing.T, index string, catDomains map[string]string) *mgmtapi.Server {
	t.Helper()
	dir := t.TempDir()
	catDir := filepath.Join(dir, "categories")
	if err := os.MkdirAll(catDir, 0o755); err != nil {
		t.Fatalf("mkdir categories: %v", err)
	}
	if index != "" {
		if err := os.WriteFile(filepath.Join(catDir, "index.json"), []byte(index), 0o644); err != nil {
			t.Fatalf("write index.json: %v", err)
		}
	}
	for name, domains := range catDomains {
		d := filepath.Join(catDir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir cat %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(d, "domains"), []byte(domains), 0o644); err != nil {
			t.Fatalf("write domains: %v", err)
		}
	}

	settingsPath := filepath.Join(dir, "config", "settings.json")
	seed := map[string]any{
		"cert_dir":       filepath.Join(dir, "certs"),
		"policies_dir":   filepath.Join(dir, "policies"),
		"logs_dir":       filepath.Join(dir, "logs"),
		"categories_dir": catDir,
	}
	data, _ := json.Marshal(seed)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	s, err := mgmtapi.NewServer(settingsPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.Scanner = stubScanner{}
	t.Cleanup(func() { s.Logs.Close() })
	return s
}

func TestCategoriesReturnsPopulatedIndex(t *testing.T) {
	index := `{
	  "updated": "2026-06-01T00:00:00Z",
	  "categories": [
	    {"name": "porn", "count": 3, "updated": "2026-06-01"},
	    {"name": "gambling", "count": 1, "updated": "2026-06-01"}
	  ]
	}`
	s := newServerWithCategories(t, index, nil)

	rr := doRequest(t, s, http.MethodGet, "/api/categories", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Categories []struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		} `json:"categories"`
		Updated string `json:"updated"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Categories) != 2 {
		t.Fatalf("got %d categories, want 2", len(body.Categories))
	}
	if body.Categories[0].Name != "porn" || body.Categories[0].Count != 3 {
		t.Errorf("first category = %+v, want porn/3", body.Categories[0])
	}
	if body.Updated != "2026-06-01T00:00:00Z" {
		t.Errorf("index meta 'updated' = %q, not surfaced", body.Updated)
	}
}

func TestCategoriesEmptyWhenNotPopulated(t *testing.T) {
	s := newServerWithCategories(t, "", nil)
	rr := doRequest(t, s, http.MethodGet, "/api/categories", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Categories []any `json:"categories"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Categories) != 0 {
		t.Errorf("expected empty categories, got %d", len(body.Categories))
	}
}

func TestNeighborsEndpointShape(t *testing.T) {
	s := newServerWithCategories(t, "", nil)
	rr := doRequest(t, s, http.MethodGet, "/api/tools/neighbors", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// The neighbor table may legitimately be empty in a sandbox, but the
	// "neighbors" key must always be present and an array (the UI does
	// `data.neighbors || []`).
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, ok := body["neighbors"]
	if !ok {
		t.Fatalf("response missing 'neighbors' key: %s", rr.Body.String())
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("'neighbors' is not an array: %v", err)
	}
}

func TestScanRejectsBadURLs(t *testing.T) {
	s := newServerWithCategories(t, "", nil)

	for _, tc := range []struct{ name, body string }{
		{"empty", `{"url":""}`},
		{"missing", `{}`},
		{"relative", `{"url":"/just/a/path"}`},
		{"non-http scheme", `{"url":"file:///etc/passwd"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(t, s, http.MethodPost, "/api/tools/scan", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestYouTubeParsing(t *testing.T) {
	s := newServerWithCategories(t, "", nil)

	// Channel handle: no network involved, deterministic.
	rr := doRequest(t, s, http.MethodPost, "/api/tools/youtube", `{"url":"https://youtube.com/@SomeHandle"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var chBody struct {
		Kind    string `json:"kind"`
		Channel string `json:"channel"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &chBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if chBody.Kind != "channel" || chBody.Channel != "@SomeHandle" {
		t.Errorf("channel parse = %+v, want channel/@SomeHandle", chBody)
	}

	// Video: the oEmbed fetch may fail offline, but kind/video_id are parsed
	// locally and must be present regardless.
	rr = doRequest(t, s, http.MethodPost, "/api/tools/youtube", `{"url":"https://www.youtube.com/watch?v=dQw4w9WgXcQ"}`)
	var vBody struct {
		Kind    string `json:"kind"`
		VideoID string `json:"video_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &vBody); err != nil {
		t.Fatalf("decode video: %v", err)
	}
	if vBody.Kind != "video" || vBody.VideoID != "dQw4w9WgXcQ" {
		t.Errorf("video parse = %+v, want video/dQw4w9WgXcQ", vBody)
	}

	// Missing url → 400.
	rr = doRequest(t, s, http.MethodPost, "/api/tools/youtube", `{}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing url: status = %d, want 400", rr.Code)
	}
}

func TestDohEndpointShapeAndValidation(t *testing.T) {
	s := newServerWithCategories(t, "", nil)

	// Missing domain → 400.
	rr := doRequest(t, s, http.MethodPost, "/api/tools/doh", `{}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing domain: status = %d, want 400", rr.Code)
	}

	// A query always returns 200 with the diagnostic shape; offline it comes
	// back SERVFAIL with an empty record set rather than erroring.
	rr = doRequest(t, s, http.MethodPost, "/api/tools/doh", `{"domain":"example.com"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body struct {
		Domain  string `json:"domain"`
		Server  string `json:"server"`
		Records []any  `json:"records"`
		Rcode   string `json:"rcode"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", body.Domain)
	}
	if body.Server == "" {
		t.Errorf("server should default when omitted")
	}
	if body.Records == nil {
		t.Errorf("records must be a (possibly empty) array, not null")
	}
}

func seedRequestRows(t *testing.T, s *mgmtapi.Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.Logs.LogRequest(logstore.RequestEntry{
			TS:        int64(1_700_000_000 + i),
			Method:    "GET",
			Host:      "example.com",
			Path:      "/page",
			Status:    200,
			Action:    "ok",
			Component: "url_filter",
			Policy:    "default",
			ClientIP:  "10.0.0.5",
			UserAgent: "test/1.0",
		}); err != nil {
			t.Fatalf("LogRequest: %v", err)
		}
	}
}

func TestLogsExportCSV(t *testing.T) {
	s := newServerWithCategories(t, "", nil)
	seedRequestRows(t, s, 3)

	q := url.Values{"kind": {"requests"}, "format": {"csv"}}
	rr := doRequest(t, s, http.MethodGet, "/api/logs/export?"+q.Encode(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, ".csv") {
		t.Errorf("Content-Disposition = %q, want a .csv attachment", cd)
	}
	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if len(lines) != 4 { // header + 3 rows
		t.Fatalf("got %d CSV lines, want 4:\n%s", len(lines), rr.Body.String())
	}
	if !strings.HasPrefix(lines[0], "ts,method,host,path,status") {
		t.Errorf("header row = %q", lines[0])
	}
	if !strings.Contains(lines[1], "example.com") || !strings.Contains(lines[1], "200") {
		t.Errorf("data row missing expected fields: %q", lines[1])
	}
}

func TestLogsExportXLSX(t *testing.T) {
	s := newServerWithCategories(t, "", nil)
	seedRequestRows(t, s, 2)

	q := url.Values{"kind": {"requests"}, "format": {"xlsx"}}
	rr := doRequest(t, s, http.MethodGet, "/api/logs/export?"+q.Encode(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "spreadsheetml") {
		t.Errorf("Content-Type = %q, want an xlsx type", ct)
	}

	data := rr.Body.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	var sheet string
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(b)
		}
	}
	for _, required := range []string{"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet1.xml"} {
		if !names[required] {
			t.Errorf("xlsx missing part %q", required)
		}
	}
	if !strings.Contains(sheet, "example.com") {
		t.Errorf("sheet does not contain seeded data:\n%s", sheet)
	}
	// Header cells should be present as inline strings.
	if !strings.Contains(sheet, "method") || !strings.Contains(sheet, "host") {
		t.Errorf("sheet missing header labels")
	}
}

func TestLogsExportValidation(t *testing.T) {
	s := newServerWithCategories(t, "", nil)

	rr := doRequest(t, s, http.MethodGet, "/api/logs/export?kind=bogus&format=csv", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad kind: status = %d, want 400", rr.Code)
	}
	rr = doRequest(t, s, http.MethodGet, "/api/logs/export?kind=requests&format=pdf", "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad format: status = %d, want 400", rr.Code)
	}
}

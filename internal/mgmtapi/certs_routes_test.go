package mgmtapi_test

import (
	"bytes"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"testing"
)

func TestCACertDownload(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/ca-cert")
	if err != nil {
		t.Fatalf("GET /api/ca-cert: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	block, _ := pem.Decode(buf.Bytes())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("response is not a PEM CERTIFICATE block")
	}
}

func TestCertsExportContainsKeyAndCert(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/certs/export")
	if err != nil {
		t.Fatalf("GET /api/certs/export: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	data := buf.Bytes()

	var sawCert, sawKey bool
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			sawCert = true
		}
		if block.Type == "EC PRIVATE KEY" {
			sawKey = true
		}
	}
	if !sawCert || !sawKey {
		t.Errorf("export bundle missing cert or key: sawCert=%v sawKey=%v", sawCert, sawKey)
	}
}

func TestCertsImportRotatesCAAndFiresCallback(t *testing.T) {
	// Build a second, independent CA bundle to import.
	_, otherTS := newTestServer(t)
	otherResp, _ := http.Get(otherTS.URL + "/api/certs/export")
	var otherBuf bytes.Buffer
	otherBuf.ReadFrom(otherResp.Body)
	otherResp.Body.Close()

	s, ts := newTestServer(t)
	rotated := false
	s.OnCARotated = func() { rotated = true }

	before := s.CA.Cert.SerialNumber.String()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "ca.pem")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	fw.Write(otherBuf.Bytes())
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/certs/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /api/certs/import: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import status = %d, want 200", resp.StatusCode)
	}

	if !rotated {
		t.Errorf("OnCARotated callback was not invoked")
	}
	if s.CA.Cert.SerialNumber.String() == before {
		t.Errorf("CA serial unchanged after import - rotation did not take effect")
	}
}

func TestCertsImportRejectsGarbage(t *testing.T) {
	_, ts := newTestServer(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "junk.pem")
	fw.Write([]byte("not a pem file"))
	mw.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/certs/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

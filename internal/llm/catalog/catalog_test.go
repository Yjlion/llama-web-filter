package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogHasDefaultAndUniqueIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range All() {
		if seen[m.ID] {
			t.Errorf("duplicate id %s", m.ID)
		}
		seen[m.ID] = true
		if len(m.Repos) == 0 || len(m.QuantPrefer) == 0 {
			t.Errorf("%s: repos/quant_prefer must be set", m.ID)
		}
	}
	if _, ok := Lookup("gemma-4-e2b"); !ok {
		t.Fatal("default model gemma-4-e2b missing from catalog")
	}
	if _, ok := Lookup("GEMMA-4-E2B"); !ok {
		t.Fatal("Lookup should be case-insensitive")
	}
}

func TestPickModelFilePrefersQuantOrderAndSkipsMMProjAndShards(t *testing.T) {
	files := []RemoteFile{
		{Name: "mmproj-model-f16.gguf", Size: 10},
		{Name: "model-Q8_0.gguf", Size: 300},
		{Name: "model-Q4_K_M-00001-of-00002.gguf", Size: 100},
		{Name: "model-Q4_K_M.gguf", Size: 200},
		{Name: "README.md", Size: 1},
	}
	got, ok := pickModelFile(files, []string{"Q4_K_M", "Q8_0"})
	if !ok || got.Name != "model-Q4_K_M.gguf" {
		t.Fatalf("pickModelFile = %v,%v want model-Q4_K_M.gguf", got, ok)
	}
	got, ok = pickModelFile(files, []string{"IQ2_XXS"})
	if !ok || got.Name != "model-Q4_K_M.gguf" {
		t.Fatalf("fallback should pick the smallest single-file gguf, got %v", got)
	}
	pf, ok := pickMMProj(files)
	if !ok || pf.Name != "mmproj-model-f16.gguf" {
		t.Fatalf("pickMMProj = %v", pf)
	}
}

// fakeHub serves the model API and file downloads with Range support.
type fakeHub struct {
	repo  string
	files map[string][]byte
	hits  map[string]int
}

func (f *fakeHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), f.repo) {
			http.NotFound(w, r)
			return
		}
		var sib []map[string]any
		for name, data := range f.files {
			sum := sha256.Sum256(data)
			sib = append(sib, map[string]any{
				"rfilename": name,
				"lfs":       map[string]any{"oid": hex.EncodeToString(sum[:]), "size": len(data)},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"siblings": sib})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		data, ok := f.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		f.hits[name]++
		if rng := r.Header.Get("Range"); strings.HasPrefix(rng, "bytes=") {
			var off int
			fmt.Sscanf(rng, "bytes=%d-", &off)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, len(data)-1, len(data)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[off:])
			return
		}
		_, _ = w.Write(data)
	})
	return mux
}

func TestDownloadResolvesVerifiesAndResumes(t *testing.T) {
	model := make([]byte, 3000)
	for i := range model {
		model[i] = byte(i)
	}
	mmproj := []byte("projector-bytes")
	fh := &fakeHub{repo: "org/test-GGUF", files: map[string][]byte{
		"test-Q4_K_M.gguf": model, "mmproj-test-f16.gguf": mmproj, "test-Q8_0.gguf": append(model, model...),
	}, hits: map[string]int{}}
	ts := httptest.NewServer(fh.handler())
	defer ts.Close()

	hub := &Hub{Endpoint: ts.URL, Client: ts.Client()}
	m := Model{ID: "test", Repos: []string{"missing/repo", "org/test-GGUF"}, QuantPrefer: []string{"Q4_K_M"}, Vision: true}
	dataDir := t.TempDir()

	// Simulate an interrupted download: a .part with the first 1000 bytes.
	dir := ModelDir(dataDir, "test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "test-Q4_K_M.gguf.part"), model[:1000], 0o644); err != nil {
		t.Fatal(err)
	}

	var prog Progress
	inst, err := hub.Download(context.Background(), dataDir, m, &prog)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if inst.Repo != "org/test-GGUF" || inst.ModelFile != "test-Q4_K_M.gguf" || inst.MMProjFile != "mmproj-test-f16.gguf" || !inst.Vision {
		t.Fatalf("manifest = %+v", inst)
	}
	got, _ := os.ReadFile(filepath.Join(dir, inst.ModelFile))
	if string(got) != string(model) {
		t.Fatal("resumed model file does not match the original bytes")
	}
	if prog.Done() != int64(len(model)+len(mmproj)) || prog.Total != prog.Done() {
		t.Errorf("progress done=%d total=%d", prog.Done(), prog.Total)
	}
	if _, ok := LoadInstalled(dataDir, "test"); !ok {
		t.Fatal("LoadInstalled should find the manifest")
	}
	if len(ListInstalled(dataDir)) != 1 {
		t.Fatal("ListInstalled should list one model")
	}

	// A second download is a no-op: files are complete and verified.
	before := fh.hits["test-Q4_K_M.gguf"]
	if _, err := hub.Download(context.Background(), dataDir, m, nil); err != nil {
		t.Fatal(err)
	}
	if fh.hits["test-Q4_K_M.gguf"] != before {
		t.Fatal("complete files must not be re-fetched")
	}
}

func TestDownloadRejectsCorruptFile(t *testing.T) {
	fh := &fakeHub{repo: "org/x", files: map[string][]byte{"x-Q4_0.gguf": []byte("good")}, hits: map[string]int{}}
	// Serve different bytes than the advertised digest.
	mux := fh.handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/resolve/") {
			_, _ = w.Write([]byte("evil"))
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()
	hub := &Hub{Endpoint: ts.URL, Client: ts.Client()}
	m := Model{ID: "x", Repos: []string{"org/x"}, QuantPrefer: []string{"Q4_0"}}
	_, err := hub.Download(context.Background(), t.TempDir(), m, nil)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
}

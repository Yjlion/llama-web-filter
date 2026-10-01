package runtime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAssetForCoversSupportedPlatforms(t *testing.T) {
	cases := []struct {
		goos, arch string
		accel      Accel
		want       string
	}{
		{"windows", "amd64", AccelCPU, "llama-b1-bin-win-cpu-x64.zip"},
		{"windows", "amd64", AccelCUDA, "llama-b1-bin-win-cuda-13.4-x64.zip"},
		{"windows", "amd64", AccelVulkan, "llama-b1-bin-win-vulkan-x64.zip"},
		{"windows", "arm64", AccelCPU, "llama-b1-bin-win-cpu-arm64.zip"},
		{"darwin", "arm64", AccelMetal, "llama-b1-bin-macos-arm64.tar.gz"},
		{"darwin", "amd64", AccelMetal, "llama-b1-bin-macos-x64.tar.gz"},
		{"linux", "amd64", AccelCPU, "llama-b1-bin-ubuntu-x64.tar.gz"},
		{"linux", "amd64", AccelCUDA, "llama-b1-bin-ubuntu-cuda-13.4-x64.tar.gz"},
		{"linux", "amd64", AccelVulkan, "llama-b1-bin-ubuntu-vulkan-x64.tar.gz"},
		{"linux", "arm64", AccelCPU, "llama-b1-bin-ubuntu-arm64.tar.gz"},
		{"linux", "arm64", AccelVulkan, "llama-b1-bin-ubuntu-vulkan-arm64.tar.gz"},
	}
	for _, c := range cases {
		a, ok := AssetFor("b1", c.goos, c.arch, c.accel)
		if !ok || a.Name != c.want {
			t.Errorf("AssetFor(%s/%s/%s) = %q,%v want %q", c.goos, c.arch, c.accel, a.Name, ok, c.want)
		}
		if !strings.HasSuffix(a.URL, "/b1/"+c.want) {
			t.Errorf("URL %q should end with /b1/%s", a.URL, c.want)
		}
	}
	if a, ok := AssetFor("b1", "windows", "amd64", AccelCUDA); !ok || len(a.Extra) != 1 {
		t.Errorf("windows CUDA must pull the cudart archive too: %+v", a)
	}
	if _, ok := AssetFor("b1", "freebsd", "amd64", AccelCPU); ok {
		t.Error("unsupported platform must report ok=false")
	}
}

func TestSafeJoinRejectsEscapes(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../x", "/etc/passwd", "a/../../b"} {
		if _, err := safeJoin(dir, bad); err == nil {
			t.Errorf("safeJoin(%q) should fail", bad)
		}
	}
	if _, err := safeJoin(dir, "build/bin/llama-server"); err != nil {
		t.Errorf("safeJoin(normal) = %v", err)
	}
}

func makeTarGz(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		mode := int64(0o644)
		if strings.HasSuffix(name, "llama-server") {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestDownloadUnpacksAndFindsServer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("archive layout differs on windows")
	}
	accel := AccelCPU
	asset, ok := AssetFor("btest", runtime.GOOS, runtime.GOARCH, accel)
	if !ok {
		t.Skip("no asset for this platform")
	}
	var payload []byte
	if strings.HasSuffix(asset.Name, ".zip") {
		payload = makeZip(t, map[string]string{"llama-server": "#!/bin/sh\necho hi\n", "libllama.so": "x"})
	} else {
		payload = makeTarGz(t, map[string]string{"build/bin/llama-server": "#!/bin/sh\necho hi\n", "build/bin/libllama.so": "x"})
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/btest/"+asset.Name) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer ts.Close()
	t.Setenv("LLAMA_CPP_RELEASE_BASE", ts.URL)

	dataDir := t.TempDir()
	var steps []string
	inst, err := Download(context.Background(), dataDir, "btest", accel, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if _, err := os.Stat(inst.Server); err != nil {
		t.Fatalf("server binary missing: %v", err)
	}
	if !strings.HasPrefix(inst.Server, InstallDir(dataDir, "btest", accel)) {
		t.Errorf("server %q not under install dir", inst.Server)
	}
	if len(steps) < 2 {
		t.Errorf("expected download+unpack progress steps, got %v", steps)
	}
	if got, ok := LoadInstalled(dataDir, "btest", accel); !ok || got.Server != inst.Server {
		t.Fatalf("LoadInstalled = %+v, %v", got, ok)
	}
	// Second call is served from the manifest, no network.
	ts.Close()
	if _, err := Download(context.Background(), dataDir, "btest", accel, nil); err != nil {
		t.Fatalf("second Download should be a no-op: %v", err)
	}
	if _, ok := FindServer(filepath.Dir(inst.Server)); !ok {
		t.Error("FindServer failed on the install dir")
	}
}

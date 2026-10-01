// Package runtime downloads a prebuilt llama.cpp release for this machine
// and supervises `llama-server` as a child process.
package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// PinnedTag is the llama.cpp release the catalog is tested against. Releases
// are nightly (bNNNN); the binary names below follow the current asset
// naming. `webfilter llm update-runtime --tag` can move it.
const PinnedTag = "b11146"

// ReleaseBase is where release assets are fetched from. LLAMA_CPP_RELEASE_BASE
// overrides it (mirrors, tests).
const ReleaseBase = "https://github.com/ggml-org/llama.cpp/releases/download"

// Accel is a llama.cpp build flavour.
type Accel string

const (
	AccelCPU    Accel = "cpu"
	AccelCUDA   Accel = "cuda"
	AccelVulkan Accel = "vulkan"
	AccelMetal  Accel = "metal"
)

// Asset is one downloadable release archive.
type Asset struct {
	Name string
	URL  string
	// Extra archives that must be unpacked alongside (CUDA runtime DLLs).
	Extra []string
}

// AssetFor maps (OS, arch, accel) to the release archive name. ok=false means
// no prebuilt exists for the combination.
func AssetFor(tag, goos, goarch string, accel Accel) (Asset, bool) {
	base := func(name string, extra ...string) (Asset, bool) {
		a := Asset{Name: name, URL: releaseBase() + "/" + tag + "/" + name}
		for _, e := range extra {
			a.Extra = append(a.Extra, releaseBase()+"/"+tag+"/"+e)
		}
		return a, true
	}
	switch goos {
	case "windows":
		switch goarch {
		case "amd64":
			switch accel {
			case AccelCUDA:
				return base("llama-"+tag+"-bin-win-cuda-13.4-x64.zip", "cudart-llama-bin-win-cuda-13.4-x64.zip")
			case AccelVulkan:
				return base("llama-" + tag + "-bin-win-vulkan-x64.zip")
			default:
				return base("llama-" + tag + "-bin-win-cpu-x64.zip")
			}
		case "arm64":
			return base("llama-" + tag + "-bin-win-cpu-arm64.zip")
		}
	case "darwin":
		switch goarch {
		case "arm64":
			return base("llama-" + tag + "-bin-macos-arm64.tar.gz")
		case "amd64":
			return base("llama-" + tag + "-bin-macos-x64.tar.gz")
		}
	case "linux":
		switch goarch {
		case "amd64":
			switch accel {
			case AccelCUDA:
				return base("llama-" + tag + "-bin-ubuntu-cuda-13.4-x64.tar.gz")
			case AccelVulkan:
				return base("llama-" + tag + "-bin-ubuntu-vulkan-x64.tar.gz")
			default:
				return base("llama-" + tag + "-bin-ubuntu-x64.tar.gz")
			}
		case "arm64":
			switch accel {
			case AccelVulkan:
				return base("llama-" + tag + "-bin-ubuntu-vulkan-arm64.tar.gz")
			default:
				return base("llama-" + tag + "-bin-ubuntu-arm64.tar.gz")
			}
		}
	}
	return Asset{}, false
}

func releaseBase() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("LLAMA_CPP_RELEASE_BASE")), "/"); v != "" {
		return v
	}
	return ReleaseBase
}

// ResolveAccel turns the configured value ("auto", "cpu", ...) into the
// flavour to download, probing the machine for "auto".
func ResolveAccel(configured string) Accel {
	if runtime.GOOS == "darwin" {
		return AccelMetal // the macOS build always carries Metal
	}
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "cpu":
		return AccelCPU
	case "cuda":
		return AccelCUDA
	case "vulkan":
		return AccelVulkan
	}
	return ProbeAccel()
}

// ProbeAccel guesses the best flavour for this machine. It only checks for
// the presence of the vendor driver, which is what the prebuilt needs at
// load time; whether the GPU is actually usable is found out by running
// the server, and the supervisor falls back to the CPU build when a GPU
// build fails to start.
func ProbeAccel() Accel {
	switch runtime.GOOS {
	case "darwin":
		return AccelMetal
	case "windows":
		sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
		if sys == "System32" {
			sys = `C:\Windows\System32`
		}
		if exists(filepath.Join(sys, "nvcuda.dll")) || lookPath("nvidia-smi") {
			return AccelCUDA
		}
		if exists(filepath.Join(sys, "vulkan-1.dll")) {
			return AccelVulkan
		}
	case "linux":
		if lookPath("nvidia-smi") || exists("/dev/nvidiactl") {
			return AccelCUDA
		}
		for _, p := range []string{
			"/usr/lib/x86_64-linux-gnu/libvulkan.so.1", "/usr/lib64/libvulkan.so.1",
			"/usr/lib/libvulkan.so.1", "/usr/lib/aarch64-linux-gnu/libvulkan.so.1",
		} {
			if exists(p) && exists("/dev/dri") {
				return AccelVulkan
			}
		}
	}
	return AccelCPU
}

func exists(p string) bool   { _, err := os.Stat(p); return err == nil }
func lookPath(n string) bool { _, err := exec.LookPath(n); return err == nil }

// ServerBinaryName is the llama-server executable name on this OS.
func ServerBinaryName() string {
	if runtime.GOOS == "windows" {
		return "llama-server.exe"
	}
	return "llama-server"
}

// InstallDir is where a runtime flavour is unpacked.
func InstallDir(dataDir, tag string, accel Accel) string {
	return filepath.Join(dataDir, "runtime", fmt.Sprintf("%s-%s-%s-%s", tag, runtime.GOOS, runtime.GOARCH, accel))
}

// FindServer locates llama-server inside an install dir (archives differ in
// whether they nest under build/bin/).
func FindServer(installDir string) (string, bool) {
	want := ServerBinaryName()
	var found string
	_ = filepath.WalkDir(installDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if !d.IsDir() && d.Name() == want {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	return found, found != ""
}

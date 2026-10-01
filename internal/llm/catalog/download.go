package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

// Installed describes a model present on disk, as recorded in the manifest
// written next to its files.
type Installed struct {
	ID         string    `json:"id"`
	Repo       string    `json:"repo"`
	ModelFile  string    `json:"model_file"`
	MMProjFile string    `json:"mmproj_file,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	SizeBytes  int64     `json:"size_bytes"`
	Vision     bool      `json:"vision"`
	Installed  time.Time `json:"installed"`
}

// ModelDir is where a model's files live under the LLM data dir.
func ModelDir(dataDir, id string) string {
	return filepath.Join(dataDir, "models", id)
}

func manifestPath(dir string) string { return filepath.Join(dir, "manifest.json") }

// LoadInstalled reads a model's manifest, or returns ok=false when the model
// is absent or incomplete.
func LoadInstalled(dataDir, id string) (Installed, bool) {
	dir := ModelDir(dataDir, id)
	data, err := os.ReadFile(manifestPath(dir))
	if err != nil {
		return Installed{}, false
	}
	var m Installed
	if err := json.Unmarshal(data, &m); err != nil {
		return Installed{}, false
	}
	if _, err := os.Stat(filepath.Join(dir, m.ModelFile)); err != nil {
		return Installed{}, false
	}
	if m.MMProjFile != "" {
		if _, err := os.Stat(filepath.Join(dir, m.MMProjFile)); err != nil {
			return Installed{}, false
		}
	}
	return m, true
}

// ListInstalled returns every model with a valid manifest under dataDir.
func ListInstalled(dataDir string) []Installed {
	entries, err := os.ReadDir(filepath.Join(dataDir, "models"))
	if err != nil {
		return nil
	}
	var out []Installed
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if m, ok := LoadInstalled(dataDir, e.Name()); ok {
			out = append(out, m)
		}
	}
	return out
}

// Remove deletes a model's files.
func Remove(dataDir, id string) error {
	if _, ok := Lookup(id); !ok {
		return fmt.Errorf("unknown model %q", id)
	}
	return os.RemoveAll(ModelDir(dataDir, id))
}

// Progress is the live state of one download, safe to read concurrently.
type Progress struct {
	Total int64
	done  atomic.Int64
	File  atomic.Pointer[string]
}

// Done is the number of bytes written so far.
func (p *Progress) Done() int64 { return p.done.Load() }

// Current is the file currently downloading.
func (p *Progress) Current() string {
	if s := p.File.Load(); s != nil {
		return *s
	}
	return ""
}

// Download fetches a model's files into dataDir, resuming partial files,
// verifying SHA-256 when the Hub published one, and writing the manifest
// last so a half-finished download never reads as installed.
func (h *Hub) Download(ctx context.Context, dataDir string, m Model, prog *Progress) (Installed, error) {
	plan, err := h.Resolve(ctx, m)
	if err != nil {
		return Installed{}, err
	}
	dir := ModelDir(dataDir, m.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Installed{}, err
	}
	if prog != nil {
		prog.Total = plan.Model.Size
		if plan.MMProj != nil {
			prog.Total += plan.MMProj.Size
		}
	}
	files := []RemoteFile{plan.Model}
	if plan.MMProj != nil {
		files = append(files, *plan.MMProj)
	}
	var total int64
	for _, f := range files {
		if prog != nil {
			name := f.Name
			prog.File.Store(&name)
		}
		dest := filepath.Join(dir, filepath.Base(f.Name))
		if err := h.fetchFile(ctx, h.FileURL(plan.Repo, f.Name), dest, f, prog); err != nil {
			return Installed{}, fmt.Errorf("download %s: %w", f.Name, err)
		}
		total += f.Size
	}
	inst := Installed{
		ID:        m.ID,
		Repo:      plan.Repo,
		ModelFile: filepath.Base(plan.Model.Name),
		SHA256:    plan.Model.SHA256,
		SizeBytes: total,
		Vision:    plan.MMProj != nil,
		Installed: time.Now().UTC(),
	}
	if plan.MMProj != nil {
		inst.MMProjFile = filepath.Base(plan.MMProj.Name)
	}
	data, _ := json.MarshalIndent(inst, "", "  ")
	tmp := manifestPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return Installed{}, err
	}
	if err := os.Rename(tmp, manifestPath(dir)); err != nil {
		return Installed{}, err
	}
	return inst, nil
}

// fetchFile downloads url to dest with resume (HTTP Range on a .part file)
// and digest verification.
func (h *Hub) fetchFile(ctx context.Context, url, dest string, want RemoteFile, prog *Progress) error {
	// Already complete and verified from a previous run.
	if st, err := os.Stat(dest); err == nil && (want.Size == 0 || st.Size() == want.Size) {
		if want.SHA256 == "" || fileSHA256(dest) == want.SHA256 {
			if prog != nil {
				prog.done.Add(st.Size())
			}
			return nil
		}
		_ = os.Remove(dest)
	}
	part := dest + ".part"
	var offset int64
	if st, err := os.Stat(part); err == nil {
		offset = st.Size()
		if want.Size > 0 && offset > want.Size {
			offset = 0
			_ = os.Remove(part)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	h.auth(req)
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	// Model files are gigabytes; the Hub client's timeout is for API calls.
	client := &http.Client{Transport: h.client().Transport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	flags := os.O_CREATE | os.O_WRONLY
	switch resp.StatusCode {
	case http.StatusPartialContent:
		flags |= os.O_APPEND
	case http.StatusOK:
		offset = 0
		flags |= os.O_TRUNC
	default:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return err
	}
	if prog != nil {
		prog.done.Add(offset)
	}
	buf := make([]byte, 1<<20)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return werr
			}
			if prog != nil {
				prog.done.Add(int64(n))
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return rerr
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if st, err := os.Stat(part); err == nil && want.Size > 0 && st.Size() != want.Size {
		return fmt.Errorf("size mismatch: got %d bytes, want %d", st.Size(), want.Size)
	}
	if want.SHA256 != "" {
		if got := fileSHA256(part); got != want.SHA256 {
			_ = os.Remove(part)
			return fmt.Errorf("sha256 mismatch: got %s, want %s", got, want.SHA256)
		}
	}
	return os.Rename(part, dest)
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ErrNotInstalled is returned when a model is configured but absent.
var ErrNotInstalled = errors.New("model not installed")

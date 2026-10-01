// Package catalog is the list of edge models llama-web-filter knows how to
// download and run, plus the Hugging Face downloader that fetches them.
//
// File names inside a GGUF repository change between uploads (quant
// suffixes, mmproj precision), so the catalog pins repositories and quant
// preferences rather than exact file names: Resolve asks the Hub's model
// API which files exist and picks the best match, and the download is
// verified against the SHA-256 the Hub publishes for each LFS blob.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed models.json
var modelsJSON []byte

// Model is one catalog entry.
type Model struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Repos are Hugging Face repositories tried in order until one has a
	// matching GGUF (and mmproj, for vision models).
	Repos []string `json:"repos"`
	// QuantPrefer is the quantization preference, best first; the first
	// one present in the repository wins.
	QuantPrefer  []string `json:"quant_prefer"`
	Vision       bool     `json:"vision"`
	ApproxSizeMB int      `json:"approx_size_mb"`
	MinRAMMB     int      `json:"min_ram_mb"`
	Context      int      `json:"context"`
}

var models []Model

func init() {
	var doc struct {
		Models []Model `json:"models"`
	}
	if err := json.Unmarshal(modelsJSON, &doc); err != nil {
		panic("llm catalog: embedded models.json is invalid: " + err.Error())
	}
	models = doc.Models
}

// All returns every catalog entry in catalog order (the default first).
func All() []Model {
	out := make([]Model, len(models))
	copy(out, models)
	return out
}

// Lookup finds a model by id, case-insensitively.
func Lookup(id string) (Model, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, m := range models {
		if strings.ToLower(m.ID) == id {
			return m, true
		}
	}
	return Model{}, false
}

// IDs lists the catalog ids, for error messages and CLI help.
func IDs() []string {
	ids := make([]string, 0, len(models))
	for _, m := range models {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return ids
}

// Files is a resolved download plan for one model: which repository, which
// GGUF, and (for vision models) which multimodal projector.
type Files struct {
	Repo   string
	Model  RemoteFile
	MMProj *RemoteFile
}

// RemoteFile is one file in a Hub repository.
type RemoteFile struct {
	Name   string
	Size   int64
	SHA256 string // lowercase hex; empty when the Hub did not report one
}

// pickModelFile chooses the GGUF for the preferred quantization. Multi-part
// files ("-00001-of-00003.gguf") and mmproj files are never candidates.
func pickModelFile(files []RemoteFile, prefer []string) (RemoteFile, bool) {
	isCandidate := func(f RemoteFile) bool {
		n := strings.ToLower(f.Name)
		return strings.HasSuffix(n, ".gguf") && !strings.Contains(n, "mmproj") && !strings.Contains(n, "-of-")
	}
	for _, q := range prefer {
		ql := strings.ToLower(q)
		for _, f := range files {
			if !isCandidate(f) {
				continue
			}
			n := strings.ToLower(f.Name)
			if strings.Contains(n, "-"+ql+".gguf") || strings.Contains(n, "_"+ql+".gguf") || strings.Contains(n, "."+ql+".gguf") || strings.HasSuffix(n, ql+".gguf") {
				return f, true
			}
		}
	}
	// Nothing in the preference list: take the smallest single-file GGUF so
	// the model at least runs; the status page shows which quant landed.
	var best RemoteFile
	for _, f := range files {
		if !isCandidate(f) {
			continue
		}
		if best.Name == "" || (f.Size > 0 && f.Size < best.Size) {
			best = f
		}
	}
	return best, best.Name != ""
}

// pickMMProj prefers an f16 projector (small anyway, and quantizing the
// vision encoder costs accuracy), then any mmproj.
func pickMMProj(files []RemoteFile) (RemoteFile, bool) {
	var any RemoteFile
	for _, f := range files {
		n := strings.ToLower(f.Name)
		if !strings.Contains(n, "mmproj") || !strings.HasSuffix(n, ".gguf") {
			continue
		}
		if strings.Contains(n, "f16") {
			return f, true
		}
		if any.Name == "" {
			any = f
		}
	}
	return any, any.Name != ""
}

// resolveFrom builds a plan from one repository's file list.
func resolveFrom(m Model, repo string, files []RemoteFile) (Files, error) {
	mf, ok := pickModelFile(files, m.QuantPrefer)
	if !ok {
		return Files{}, fmt.Errorf("%s: no single-file GGUF in %s", m.ID, repo)
	}
	plan := Files{Repo: repo, Model: mf}
	if m.Vision {
		pf, ok := pickMMProj(files)
		if !ok {
			return Files{}, fmt.Errorf("%s: no mmproj (vision projector) in %s", m.ID, repo)
		}
		plan.MMProj = &pf
	}
	return plan, nil
}

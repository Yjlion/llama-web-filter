package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultHubEndpoint is the Hugging Face Hub. HF_ENDPOINT overrides it, which
// is the convention the official clients use for mirrors.
const DefaultHubEndpoint = "https://huggingface.co"

// Hub talks to a Hugging Face-compatible Hub: the model API for file
// listings and `resolve` URLs for downloads.
type Hub struct {
	Endpoint string
	Client   *http.Client
	// Token is an optional access token for gated repositories.
	Token string
}

// NewHub returns a Hub for DefaultHubEndpoint (or HF_ENDPOINT / HF_TOKEN
// from the environment).
func NewHub() *Hub {
	ep := strings.TrimRight(strings.TrimSpace(os.Getenv("HF_ENDPOINT")), "/")
	if ep == "" {
		ep = DefaultHubEndpoint
	}
	return &Hub{
		Endpoint: ep,
		Client:   &http.Client{Timeout: 60 * time.Second},
		Token:    strings.TrimSpace(os.Getenv("HF_TOKEN")),
	}
}

func (h *Hub) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

func (h *Hub) auth(req *http.Request) {
	if h.Token != "" {
		req.Header.Set("Authorization", "Bearer "+h.Token)
	}
	req.Header.Set("User-Agent", "llama-web-filter")
}

// ListFiles returns the files in a repository's main branch with their LFS
// sizes and SHA-256 digests.
func (h *Hub) ListFiles(ctx context.Context, repo string) ([]RemoteFile, error) {
	url := fmt.Sprintf("%s/api/models/%s?blobs=true", h.Endpoint, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	h.auth(req)
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrRepoNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub: %s: HTTP %d", repo, resp.StatusCode)
	}
	var doc struct {
		Siblings []struct {
			Name string `json:"rfilename"`
			Size int64  `json:"size"`
			LFS  *struct {
				OID    string `json:"oid"`
				SHA256 string `json:"sha256"`
				Size   int64  `json:"size"`
			} `json:"lfs"`
		} `json:"siblings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("hub: %s: decode: %w", repo, err)
	}
	out := make([]RemoteFile, 0, len(doc.Siblings))
	for _, s := range doc.Siblings {
		f := RemoteFile{Name: s.Name, Size: s.Size}
		if s.LFS != nil {
			if s.LFS.Size > 0 {
				f.Size = s.LFS.Size
			}
			switch {
			case len(s.LFS.SHA256) == 64:
				f.SHA256 = strings.ToLower(s.LFS.SHA256)
			case len(s.LFS.OID) == 64:
				f.SHA256 = strings.ToLower(s.LFS.OID)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// ErrRepoNotFound is returned when a repository does not exist or is gated
// for this client.
var ErrRepoNotFound = errors.New("repository not found")

// FileURL is the download URL for a file in a repository's main branch.
func (h *Hub) FileURL(repo, name string) string {
	return fmt.Sprintf("%s/%s/resolve/main/%s", h.Endpoint, repo, name)
}

// Resolve picks the repository and files to download for a model, trying
// each configured repository in order.
func (h *Hub) Resolve(ctx context.Context, m Model) (Files, error) {
	var errs []error
	for _, repo := range m.Repos {
		files, err := h.ListFiles(ctx, repo)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", repo, err))
			continue
		}
		plan, err := resolveFrom(m, repo, files)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return plan, nil
	}
	if len(errs) == 0 {
		return Files{}, fmt.Errorf("%s: no repositories configured", m.ID)
	}
	return Files{}, fmt.Errorf("%s: no usable repository: %w", m.ID, errors.Join(errs...))
}

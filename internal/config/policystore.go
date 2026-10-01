package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/yjlion/llama-web-filter/internal/models"
)

// ErrNotFound is returned when a policy name has no matching file.
var ErrNotFound = errors.New("policy not found")

// ErrExists is returned when creating a policy whose sanitized filename
// already exists.
var ErrExists = errors.New("policy already exists")

var unsafeFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)

// SafeName sanitizes a policy name into a filesystem-safe filename stem,
// mirroring the Python original exactly: re.sub(r"[^a-zA-Z0-9_\-]", "_", name).
func SafeName(name string) string {
	return unsafeFilenameChars.ReplaceAllString(name, "_")
}

// PolicyStore reads/writes policies/*.json, one file per policy, filename
// derived from SafeName(policy.Name)+".json" - the file is the source of
// truth, exactly as in the Python original.
type PolicyStore struct {
	Dir string
}

func NewPolicyStore(dir string) *PolicyStore {
	return &PolicyStore{Dir: dir}
}

func (s *PolicyStore) pathFor(safeName string) string {
	return filepath.Join(s.Dir, safeName+".json")
}

// List returns every policy in the directory, sorted by filename (matches
// the Python original's alphabetical-file-order tie-breaking within a
// PolicyRouter matching tier). Returns an empty slice (not an error) if the
// directory doesn't exist yet.
func (s *PolicyStore) List() ([]models.Policy, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return []models.Policy{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policies dir %s: %w", s.Dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	policies := make([]models.Policy, 0, len(names))
	for _, n := range names {
		p, err := s.loadFile(filepath.Join(s.Dir, n))
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *PolicyStore) loadFile(path string) (models.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return models.Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}
	var p models.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return models.Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return p, nil
}

// Get looks up a policy by name (matched against SafeName(name)+".json").
func (s *PolicyStore) Get(name string) (models.Policy, error) {
	path := s.pathFor(SafeName(name))
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return models.Policy{}, ErrNotFound
	}
	return s.loadFile(path)
}

// Create writes a new policy file, failing with ErrExists if the sanitized
// filename is already taken.
func (s *PolicyStore) Create(p models.Policy) error {
	path := s.pathFor(SafeName(p.Name))
	if _, err := os.Stat(path); err == nil {
		return ErrExists
	}
	return s.write(path, p)
}

// Update replaces the policy currently stored under oldName with p. If
// p.Name sanitizes to a different filename than oldName, the file is
// renamed (failing with ErrExists if the target name collides with a
// different existing policy).
func (s *PolicyStore) Update(oldName string, p models.Policy) error {
	oldPath := s.pathFor(SafeName(oldName))
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return ErrNotFound
	}
	newPath := s.pathFor(SafeName(p.Name))
	if newPath != oldPath {
		if _, err := os.Stat(newPath); err == nil {
			return ErrExists
		}
	}
	if err := s.write(newPath, p); err != nil {
		return err
	}
	if newPath != oldPath {
		return os.Remove(oldPath)
	}
	return nil
}

// Delete removes the policy file matching name.
func (s *PolicyStore) Delete(name string) error {
	path := s.pathFor(SafeName(name))
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("delete policy %s: %w", path, err)
	}
	return nil
}

func (s *PolicyStore) write(path string, p models.Policy) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	return atomicWriteFile(path, data)
}

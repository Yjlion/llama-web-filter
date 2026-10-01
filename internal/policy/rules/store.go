package rules

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileName is the rules document's name inside the config directory.
const FileName = "rules.json"

// PathFor returns the rules file path next to settings.json.
func PathFor(settingsPath string) string {
	return filepath.Join(filepath.Dir(settingsPath), FileName)
}

// Store reads and writes the rules file. Writes are atomic (temp file +
// rename) so a watcher never sees a half-written document.
type Store struct {
	Path string
	mu   sync.Mutex
}

// NewStore returns a store for path.
func NewStore(path string) *Store { return &Store{Path: path} }

// Load reads the file; a missing file is an empty document.
func (s *Store) Load() (File, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return File{Devices: map[string][]string{}, Rules: []Rule{}}, nil
	}
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parse %s: %w", s.Path, err)
	}
	if f.Devices == nil {
		f.Devices = map[string][]string{}
	}
	if f.Rules == nil {
		f.Rules = []Rule{}
	}
	for i := range f.Rules {
		if f.Rules[i].ID == "" {
			f.Rules[i].ID = NewID()
		}
	}
	SortStable(f.Rules)
	return f, nil
}

// Save writes the whole document.
func (s *Store) Save(f File) error {
	if f.Devices == nil {
		f.Devices = map[string][]string{}
	}
	if f.Rules == nil {
		f.Rules = []Rule{}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Add validates and appends a rule, assigning an id and timestamp.
func (s *Store) Add(r Rule) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.Load()
	if err != nil {
		return Rule{}, err
	}
	if err := Validate(&r, f.Devices); err != nil {
		return Rule{}, err
	}
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.Created.IsZero() {
		r.Created = time.Now().UTC()
	}
	for _, e := range f.Rules {
		if e.ID == r.ID {
			return Rule{}, fmt.Errorf("rule %s already exists", r.ID)
		}
	}
	f.Rules = append(f.Rules, r)
	return r, s.Save(f)
}

// ErrNotFound is returned for an unknown rule id.
var ErrNotFound = errors.New("rule not found")

// Update replaces the rule with r.ID.
func (s *Store) Update(r Rule) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.Load()
	if err != nil {
		return Rule{}, err
	}
	if err := Validate(&r, f.Devices); err != nil {
		return Rule{}, err
	}
	for i, e := range f.Rules {
		if e.ID == r.ID {
			if r.Created.IsZero() {
				r.Created = e.Created
			}
			f.Rules[i] = r
			return r, s.Save(f)
		}
	}
	return Rule{}, ErrNotFound
}

// Delete removes a rule.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.Load()
	if err != nil {
		return err
	}
	for i, e := range f.Rules {
		if e.ID == id {
			f.Rules = append(f.Rules[:i], f.Rules[i+1:]...)
			return s.Save(f)
		}
	}
	return ErrNotFound
}

// SetEnabled toggles a rule.
func (s *Store) SetEnabled(id string, enabled bool) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.Load()
	if err != nil {
		return Rule{}, err
	}
	for i := range f.Rules {
		if f.Rules[i].ID == id {
			f.Rules[i].Enabled = enabled
			return f.Rules[i], s.Save(f)
		}
	}
	return Rule{}, ErrNotFound
}

// SetDevices replaces the device aliases.
func (s *Store) SetDevices(devices map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.Load()
	if err != nil {
		return err
	}
	clean := map[string][]string{}
	for name, members := range devices {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		clean[name] = cleanList(members)
	}
	f.Devices = clean
	return s.Save(f)
}

// DeviceNames lists aliases, sorted, for prompts and the UI.
func DeviceNames(devices map[string][]string) []string {
	names := make([]string, 0, len(devices))
	for n := range devices {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// NewID returns a short random id.
func NewID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "r_" + hex.EncodeToString(b[:])
}

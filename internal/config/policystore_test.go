package config_test

import (
	"testing"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/models"
)

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"My Policy":    "My_Policy",
		"kids-laptop":  "kids-laptop",
		"office_wifi":  "office_wifi",
		"a/b\\c:d*e?f": "a_b_c_d_e_f",
		"日本語":          "___",
	}
	for in, want := range cases {
		if got := config.SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyStoreCRUD(t *testing.T) {
	store := config.NewPolicyStore(t.TempDir())

	// List on an empty/nonexistent dir returns an empty slice, not an error.
	list, err := store.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("List() = %v, %v; want empty, nil", list, err)
	}

	p := models.NewPolicy()
	p.Name = "kids"
	p.SourceIPs = []string{"192.168.1.0/24"}
	if err := store.Create(p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Create(p); err != config.ErrExists {
		t.Fatalf("Create duplicate: got %v, want ErrExists", err)
	}

	got, err := store.Get("kids")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "kids" || len(got.SourceIPs) != 1 || got.SourceIPs[0] != "192.168.1.0/24" {
		t.Errorf("Get() = %+v, want name=kids source_ips=[192.168.1.0/24]", got)
	}

	// Update, including a rename.
	got.SourceIPs = append(got.SourceIPs, "10.0.0.5")
	got.Name = "kids-renamed"
	if err := store.Update("kids", got); err != nil {
		t.Fatalf("Update (rename): %v", err)
	}
	if _, err := store.Get("kids"); err != config.ErrNotFound {
		t.Fatalf("Get(old name) after rename: got %v, want ErrNotFound", err)
	}
	renamed, err := store.Get("kids-renamed")
	if err != nil || len(renamed.SourceIPs) != 2 {
		t.Fatalf("Get(new name) after rename: %+v, %v", renamed, err)
	}

	if err := store.Delete("kids-renamed"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete("kids-renamed"); err != config.ErrNotFound {
		t.Fatalf("Delete already-deleted: got %v, want ErrNotFound", err)
	}
}

func TestPolicyStoreUpdateRenameCollision(t *testing.T) {
	store := config.NewPolicyStore(t.TempDir())
	a := models.NewPolicy()
	a.Name = "a"
	b := models.NewPolicy()
	b.Name = "b"
	if err := store.Create(a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	if err := store.Create(b); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	// Renaming "a" to "b" should collide with the existing "b" policy.
	a.Name = "b"
	if err := store.Update("a", a); err != config.ErrExists {
		t.Fatalf("Update rename collision: got %v, want ErrExists", err)
	}
}

func TestPolicyStoreListSortedByFilename(t *testing.T) {
	store := config.NewPolicyStore(t.TempDir())
	for _, name := range []string{"zebra", "apple", "mango"} {
		p := models.NewPolicy()
		p.Name = name
		if err := store.Create(p); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}
	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 || list[0].Name != "apple" || list[1].Name != "mango" || list[2].Name != "zebra" {
		names := make([]string, len(list))
		for i, p := range list {
			names[i] = p.Name
		}
		t.Errorf("List() order = %v, want [apple mango zebra]", names)
	}
}

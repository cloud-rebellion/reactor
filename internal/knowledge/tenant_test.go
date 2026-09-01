package knowledge

import (
	"context"
	"errors"
	"testing"
)

// TestCorpusTenancy pins the scoping rule that lets members keep the knowledge
// base instead of losing it to a blanket admin gate.
//
// The corpus had no tenant concept at all, so /knowledge served every tenant's
// post-mortems (workflow slugs, step names, and synthesized diagnostics) to any
// member while /postmortems refused them. Gating the whole page to admins
// closed the leak but took a real feature away from members, and the corpus is
// meant to be the thing workflow authors read.
//
// The rule: an entry with NO tenant is global (the seeded playbooks, anything
// an admin authors estate-wide) and everyone sees it. An entry stamped with a
// tenant belongs to that tenant alone. Automatic post-mortems are stamped from
// the run, so the leak closes without hiding the shared material.
func TestCorpusTenancy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	global, err := s.Add(ctx, Entry{
		Frontmatter: Frontmatter{Topic: "playbooks", Title: "How to write a workflow", CreatedBy: "seed"},
		Body:        "shared guidance",
	})
	if err != nil {
		t.Fatal(err)
	}
	acme, err := s.Add(ctx, Entry{
		Frontmatter: Frontmatter{Topic: "post-mortems", Title: "acme-payroll failed", CreatedBy: "claude", Tenant: "acme"},
		Body:        "err=stripe 402 for cus_ACME",
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Add(ctx, Entry{
		Frontmatter: Frontmatter{Topic: "post-mortems", Title: "globex billing failed", CreatedBy: "claude", Tenant: "globex"},
		Body:        "err=card_declined for cus_GLOBEX",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a member sees global plus their own tenant", func(t *testing.T) {
		got, err := s.ListForTenant(ctx, "", "acme")
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, e := range got {
			ids[e.Frontmatter.ID] = true
		}
		if !ids[global.Frontmatter.ID] {
			t.Error("member cannot see the global (untenanted) entry; the shared corpus must stay readable")
		}
		if !ids[acme.Frontmatter.ID] {
			t.Error("member cannot see their OWN tenant's entry")
		}
		if ids[other.Frontmatter.ID] {
			t.Error("CROSS-TENANT LEAK: member saw another tenant's post-mortem in the list")
		}
	})

	t.Run("an admin (empty scope) sees everything", func(t *testing.T) {
		got, err := s.ListForTenant(ctx, "", "")
		if err != nil {
			t.Fatal(err)
		}
		// The store seeds a starter corpus, so assert on presence of all three
		// fixtures rather than an exact count.
		ids := map[string]bool{}
		for _, e := range got {
			ids[e.Frontmatter.ID] = true
		}
		for _, want := range []Entry{global, acme, other} {
			if !ids[want.Frontmatter.ID] {
				t.Errorf("admin (unscoped) cannot see %q", want.Frontmatter.Title)
			}
		}
	})

	t.Run("topic filter still applies within the scope", func(t *testing.T) {
		got, err := s.ListForTenant(ctx, "post-mortems", "acme")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Frontmatter.ID != acme.Frontmatter.ID {
			t.Fatalf("topic+tenant filter returned %d entries, want just acme's", len(got))
		}
	})

	t.Run("direct fetch of another tenant's entry is not found", func(t *testing.T) {
		if _, err := s.GetForTenant(ctx, other.Frontmatter.ID, "acme"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetForTenant across the boundary returned %v, want ErrNotFound; guessing an id must not work either", err)
		}
		// Own and global still resolve.
		if _, err := s.GetForTenant(ctx, acme.Frontmatter.ID, "acme"); err != nil {
			t.Fatalf("own entry not fetchable: %v", err)
		}
		if _, err := s.GetForTenant(ctx, global.Frontmatter.ID, "acme"); err != nil {
			t.Fatalf("global entry not fetchable: %v", err)
		}
		// Admin scope reaches all.
		if _, err := s.GetForTenant(ctx, other.Frontmatter.ID, ""); err != nil {
			t.Fatalf("admin cannot fetch a tenant entry: %v", err)
		}
	})

	t.Run("tenant survives a round trip through disk", func(t *testing.T) {
		reloaded, err := New(s.Root)
		if err != nil {
			t.Fatal(err)
		}
		e, err := reloaded.Get(ctx, acme.Frontmatter.ID)
		if err != nil {
			t.Fatal(err)
		}
		if e.Frontmatter.Tenant != "acme" {
			t.Fatalf("tenant did not persist in frontmatter, got %q; scoping would silently fail after a restart", e.Frontmatter.Tenant)
		}
	})
}

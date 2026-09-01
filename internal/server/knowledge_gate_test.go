package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/knowledge"
)

// knowledgeFixture writes two entries: one shared playbook with no tenant, and
// one post-mortem stamped to another tenant, carrying the workflow slug, step
// name and synthesized Step diagnostics the generator emits (see internal/postmortem).
func knowledgeFixture(t *testing.T) *knowledge.Store {
	t.Helper()
	root := t.TempDir()
	ks, err := knowledge.New(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := ks.Add(ctx, knowledge.Entry{
		Frontmatter: knowledge.Frontmatter{
			Topic: "playbooks", Title: "How to write a workflow", CreatedBy: "seed",
		},
		Body: "shared guidance every tenant should read",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Add(ctx, knowledge.Entry{
		Frontmatter: knowledge.Frontmatter{
			Topic: "post-mortems", Title: "acme-payroll run failed",
			CreatedBy: "claude", Tenant: "tenant-b",
		},
		Body: `Root cause: workflow acme-payroll step charge-card failed with
err="stripe 402 card_declined for customer cus_TENANTB_SECRET"`,
	}); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(root, "post-mortems"), 0o700)
	return ks
}

// TestKnowledgeIsTenantScopedNotAdminOnly pins the corpus boundary.
//
// The leak: /postmortems gates on requireAdmin, but /knowledge served the SAME
// corpus from the member router with no filter, so a member saw every tenant's
// post-mortem bodies. The blunt fix (admin-gate the page) closed it by deleting
// a feature members are supposed to have, since the corpus is what workflow
// authors read.
//
// The rule instead: untenanted entries are shared and everyone sees them;
// entries stamped with a tenant belong to that tenant. Post-mortems are stamped
// from the run, so the sensitive material scopes while the playbooks stay
// shared.
func TestKnowledgeIsTenantScopedNotAdminOnly(t *testing.T) {
	t.Parallel()
	s := &Server{Knowledge: knowledgeFixture(t), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	get := func(u *auth.User) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/knowledge", nil)
		if u != nil {
			req = req.WithContext(withUser(req.Context(), *u))
		}
		rec := httptest.NewRecorder()
		s.knowledge(rec, req)
		return rec.Code, rec.Body.String()
	}

	member := auth.User{ID: "m", Role: auth.RoleMember, TenantID: "tenant-a"}
	code, body := get(&member)
	if code != http.StatusOK {
		t.Fatalf("member got %d from /knowledge, want 200; the corpus must stay readable rather than be gated away", code)
	}
	if strings.Contains(body, "acme-payroll") || strings.Contains(body, "cus_TENANTB_SECRET") {
		t.Fatal("CROSS-TENANT LEAK: member in tenant-a saw tenant-b's post-mortem through /knowledge")
	}
	if !strings.Contains(body, "How to write a workflow") {
		t.Fatal("member cannot see the shared playbook; scoping must not hide untenanted entries")
	}

	admin := auth.User{ID: "a", Role: auth.RoleAdmin, TenantID: "tenant-a"}
	if code, body := get(&admin); code != http.StatusOK || !strings.Contains(body, "acme-payroll") {
		t.Fatalf("admin got %d and cannot see the tenant post-mortem; an unscoped viewer must see everything", code)
	}
}

// TestKnowledgeDetailIsTenantScoped: guessing an id must not reach across the
// boundary either, and the answer is 404 rather than 403 so existence is not
// confirmed.
func TestKnowledgeDetailIsTenantScoped(t *testing.T) {
	t.Parallel()
	ks := knowledgeFixture(t)
	s := &Server{Knowledge: ks, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	entries, err := ks.List(context.Background(), "post-mortems")
	if err != nil || len(entries) == 0 {
		t.Fatalf("fixture not loaded: %d entries, err=%v", len(entries), err)
	}
	id := entries[0].Frontmatter.ID

	req := httptest.NewRequest(http.MethodGet, "/knowledge/"+id, nil)
	req = req.WithContext(withUser(req.Context(), auth.User{ID: "m", Role: auth.RoleMember, TenantID: "tenant-a"}))
	req = withChiParam(req, "id", id)
	rec := httptest.NewRecorder()
	s.knowledgeDetail(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("member fetched another tenant's entry directly: got %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "cus_TENANTB_SECRET") {
		t.Fatal("the other tenant's body leaked through the detail view")
	}
}

// TestKnowledgeNavIsMemberVisible: the corpus is a member feature again, so the
// nav must show it. A link members cannot use is the failure mode the admin
// gate introduced.
func TestKnowledgeNavIsMemberVisible(t *testing.T) {
	t.Parallel()
	for _, it := range navItems {
		if it.href == "/knowledge" {
			if it.adminOnly {
				t.Fatal("/knowledge is admin-only in the nav, but its handlers are tenant-scoped and member-readable")
			}
			return
		}
	}
	t.Fatal("/knowledge is missing from navItems")
}

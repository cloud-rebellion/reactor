package journal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestTenantIsolationIsRealNow is the test that could not be written before.
//
// CreateWorkflow's INSERT omitted tenant_id, so every workflow took the schema
// default and no supported code path could put one in another tenant. The
// isolation machinery built on top (viewerScope, WorkflowTenant, the
// cross-tenant grant guard, per-tenant plans and quotas) was therefore
// unfalsifiable: the guard compared two values that were always equal, and no
// test could construct the two-tenant state that would expose it.
func TestTenantIsolationIsRealNow(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_a", "shared-slug", "h", "0.1.0", json.RawMessage(`{}`), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_b", "shared-slug", "h", "0.1.0", json.RawMessage(`{}`), "tenant-b"); err != nil {
		// Two tenants owning the same slug is exactly what UNIQUE (tenant_id,
		// slug) permits, and what the unscoped resolver got wrong.
		t.Fatalf("per-tenant slug uniqueness should allow this: %v", err)
	}

	// Each tenant resolves ITS OWN workflow, not whichever was created last.
	gotA, err := j.WorkflowIDBySlugInTenant(ctx, "shared-slug", "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if gotA != "wf_a" {
		t.Fatalf("tenant-a resolved %q, want wf_a: the resolver crossed the tenant boundary", gotA)
	}
	gotB, err := j.WorkflowIDBySlugInTenant(ctx, "shared-slug", "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if gotB != "wf_b" {
		t.Fatalf("tenant-b resolved %q, want wf_b", gotB)
	}
	owners, err := j.WorkflowTenantsBySlug(ctx, "shared-slug")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(owners, ",") != "tenant-a,tenant-b" {
		t.Fatalf("workflow slug owners = %v, want [tenant-a tenant-b]", owners)
	}

	// A tenant that owns nothing gets nothing rather than someone else's row.
	if _, err := j.WorkflowIDBySlugInTenant(ctx, "shared-slug", "tenant-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unrelated tenant got %v, want ErrNotFound", err)
	}

	// WorkflowTenant reports the real owner, which is what the read-path guards
	// (dashboard.go, workflow_lifecycle.go) compare against viewerScope.
	owner, err := j.WorkflowTenant(ctx, "wf_b")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "tenant-b" {
		t.Fatalf("WorkflowTenant = %q, want tenant-b", owner)
	}

	// And listing is scoped.
	listA, err := j.ListWorkflowsByTenant(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(listA) != 1 || listA[0].ID != "wf_a" {
		t.Fatalf("tenant-a listing = %+v, want only wf_a", listA)
	}
}

// TestCrossTenantGrantGuardCanActuallyFire is the payoff. The guard shipped in
// the 2026-07-07 pass as "the data-layer half of the cross-tenant
// secret-disclosure fix", but with every workflow and credential pinned to one
// tenant its comparison was permanently false. It could not fire, and no test
// could show that it did.
func TestCrossTenantGrantGuardCanActuallyFire(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_a", "wf-a", "h", "0.1.0", json.RawMessage(`{}`), "tenant-a"); err != nil {
		t.Fatal(err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := j.db.ExecContext(ctx, j.bind(q), args...); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	mustExec(`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ($1,$2,$3,$4,$5)`,
		"cred_a", "tenant-a", "ca", "svc", []byte("x"))
	mustExec(`INSERT INTO credentials (id, tenant_id, name, service, blob) VALUES ($1,$2,$3,$4,$5)`,
		"cred_b", "tenant-b", "cb", "svc", []byte("x"))

	if err := j.GrantSecret(ctx, "wf_a", "cred_b", "tester", ""); err == nil {
		t.Fatal("granting tenant-a's workflow access to tenant-b's credential must be refused")
	}
	if err := j.GrantSecret(ctx, "wf_a", "cred_a", "tester", ""); err != nil {
		t.Fatalf("same-tenant grant must still work: %v", err)
	}
	// Revoke is guarded on the same axis.
	if err := j.RevokeSecret(ctx, "wf_a", "cred_b"); err == nil {
		t.Fatal("cross-tenant revoke must be refused")
	}
}

// TestNotificationChannelsAreTenantScoped closes a member-visible metadata
// leak. A channel is a top-level entity reachable only by id, so it had no
// tenant anchor at all and ListNotificationChannels returned every channel in
// the install. /notifications is admin-gated, but the MEMBER-facing workflow
// detail page builds its attach-channel <select> from that same unscoped list,
// so any member could read back the id, name and kind of every alert channel an
// admin had configured, and post-tenancy every other tenant's too.
func TestNotificationChannelsAreTenantScoped(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	cfg := json.RawMessage(`{"url":"https://hooks.slack.com/x"}`)

	if _, err := j.CreateNotificationChannelInTenant(ctx, "acme", "acme-alerts", ChannelKindSlackWebhook, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateNotificationChannelInTenant(ctx, "globex", "globex-alerts", ChannelKindSlackWebhook, cfg); err != nil {
		t.Fatal(err)
	}

	acme, err := j.ListNotificationChannelsByTenant(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(acme) != 1 || acme[0].Name != "acme-alerts" {
		names := make([]string, 0, len(acme))
		for _, c := range acme {
			names = append(names, c.Name)
		}
		t.Fatalf("acme sees %v, want only acme-alerts", names)
	}
	if acme[0].TenantID != "acme" {
		t.Fatalf("owner = %q, want acme", acme[0].TenantID)
	}

	// A tenant that owns none sees none, rather than everyone else's.
	none, err := j.ListNotificationChannelsByTenant(ctx, "initech")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("unrelated tenant sees %d channels, want 0", len(none))
	}

	// The unscoped list is still whole-install, which is correct for a global
	// admin and is exactly why the member-facing page must not call it.
	all, err := j.ListNotificationChannels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("admin list = %d, want 2", len(all))
	}

	// The unscoped CREATE entry point still lands in the default tenant, so the
	// CLI and any legacy caller keep working.
	if _, err := j.CreateNotificationChannel(ctx, "legacy", ChannelKindSlackWebhook, cfg); err != nil {
		t.Fatal(err)
	}
	def, err := j.ListNotificationChannelsByTenant(ctx, DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(def) != 1 || def[0].Name != "legacy" {
		t.Fatalf("default tenant = %+v, want only legacy", def)
	}
}

// TestChannelNameIsUniquePerTenantNotGlobally covers the half of the channel
// tenancy work that 0026 deliberately left alone. Adding tenant_id scoped the
// READS, but `name TEXT NOT NULL UNIQUE` still made the namespace global: two
// tenants could not both own "ops-slack", and because a create failed loudly on
// a name someone else held, it was a cross-tenant existence oracle. 0027 narrows
// it to (tenant_id, name).
func TestChannelNameIsUniquePerTenantNotGlobally(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	cfg := json.RawMessage(`{"url":"https://hooks.slack.com/x"}`)

	if _, err := j.CreateNotificationChannelInTenant(ctx, "acme", "ops-slack", ChannelKindSlackWebhook, cfg); err != nil {
		t.Fatal(err)
	}
	// The whole point: the same name in another tenant is not a conflict, and
	// therefore reveals nothing about what acme owns.
	if _, err := j.CreateNotificationChannelInTenant(ctx, "globex", "ops-slack", ChannelKindSlackWebhook, cfg); err != nil {
		t.Fatalf("globex must be able to own the same channel name as acme: %v", err)
	}
	// Still unique inside a tenant, so the constraint was narrowed, not dropped.
	_, err := j.CreateNotificationChannelInTenant(ctx, "acme", "ops-slack", ChannelKindSlackWebhook, cfg)
	if !errors.Is(err, ErrChannelNameTaken) {
		t.Fatalf("duplicate within one tenant returned %v, want ErrChannelNameTaken", err)
	}
	// The sentinel must not carry the driver text: the handler renders this and a
	// raw constraint error leaks the schema.
	if strings.Contains(strings.ToLower(err.Error()), "constraint") {
		t.Fatalf("ErrChannelNameTaken leaks driver detail: %v", err)
	}

	// Both rows exist and each tenant sees only its own.
	for tenant := range map[string]bool{"acme": true, "globex": true} {
		list, lerr := j.ListNotificationChannelsByTenant(ctx, tenant)
		if lerr != nil {
			t.Fatal(lerr)
		}
		if len(list) != 1 || list[0].Name != "ops-slack" || list[0].TenantID != tenant {
			t.Fatalf("%s sees %+v, want exactly its own ops-slack", tenant, list)
		}
	}
}

// TestCreateWorkflowDefaultsToDefaultTenant keeps the unscoped entry point
// behaving exactly as before for the CLI, MCP and codegen callers that have no
// tenant context.
func TestCreateWorkflowDefaultsToDefaultTenant(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflow(ctx, "wf_x", "unscoped", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	owner, err := j.WorkflowTenant(ctx, "wf_x")
	if err != nil {
		t.Fatal(err)
	}
	if owner != DefaultTenant {
		t.Fatalf("unscoped CreateWorkflow put the row in %q, want %q", owner, DefaultTenant)
	}
	// An empty tenant argument means the same thing, not an empty string owner.
	if err := j.CreateWorkflowInTenant(ctx, "wf_y", "explicit-empty", "h", "0.1.0", json.RawMessage(`{}`), ""); err != nil {
		t.Fatal(err)
	}
	owner, _ = j.WorkflowTenant(ctx, "wf_y")
	if owner != DefaultTenant {
		t.Fatalf("empty tenant argument produced %q, want %q", owner, DefaultTenant)
	}
}

package journal

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestCrossTenantRelationsAreRefused covers the two relations that never checked
// tenants. GrantSecret was the ONLY relation in the schema that compared the
// owners of its two endpoints; a chain trigger and a notification route both
// linked two owned things with no comparison at all.
//
// For routes the comparison was literally impossible until migration 0026 gave
// notification_channels a tenant_id, which is why it was never written.
func TestCrossTenantRelationsAreRefused(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	mk := func(id, slug, tenant string) {
		t.Helper()
		if err := j.CreateWorkflowInTenant(ctx, id, slug, "h", "0.1.0", json.RawMessage(`{}`), tenant); err != nil {
			t.Fatal(err)
		}
	}
	mk("wf_acme_a", "a", "acme")
	mk("wf_acme_b", "b", "acme")
	mk("wf_globex", "g", "globex")

	t.Run("chain trigger", func(t *testing.T) {
		// A cross-tenant chain is worse than a visibility leak: acme's completed
		// run would start globex's workflow and hand it acme's run output.
		_, err := j.CreateChainTrigger(ctx, "wf_globex", "wf_acme_a", "succeeded")
		if err == nil {
			t.Fatal("a chain from acme's workflow into globex's must be refused")
		}
		if !strings.Contains(err.Error(), "cross-tenant") {
			t.Fatalf("error should name the reason, got: %v", err)
		}
		// Same-tenant still works.
		if _, err := j.CreateChainTrigger(ctx, "wf_acme_b", "wf_acme_a", "succeeded"); err != nil {
			t.Fatalf("same-tenant chain must still work: %v", err)
		}
		triggers, err := j.ListTriggersForWorkflow(ctx, "wf_acme_b")
		if err != nil || len(triggers) != 1 || triggers[0].TenantID != "acme" {
			t.Fatalf("chain trigger did not inherit downstream tenant: %+v, %v", triggers, err)
		}
		// A nonexistent endpoint is refused rather than silently succeeding,
		// which is how phantom grants got in through MCP and the CLI.
		if _, err := j.CreateChainTrigger(ctx, "wf_acme_b", "wf_ghost", "succeeded"); err == nil {
			t.Fatal("a chain naming a nonexistent workflow must be refused")
		}
	})

	t.Run("notification route", func(t *testing.T) {
		cfg := json.RawMessage(`{"url":"https://hooks.slack.com/x"}`)
		acmeCh, err := j.CreateNotificationChannelInTenant(ctx, "acme", "acme-ops", ChannelKindSlackWebhook, cfg)
		if err != nil {
			t.Fatal(err)
		}
		globexCh, err := j.CreateNotificationChannelInTenant(ctx, "globex", "globex-ops", ChannelKindSlackWebhook, cfg)
		if err != nil {
			t.Fatal(err)
		}

		// Routing acme's workflow at globex's channel would deliver acme's run
		// slug, error text and dashboard URL into globex's Slack.
		if err := j.AddNotificationRoute(ctx, "wf_acme_a", globexCh, "failed"); err == nil {
			t.Fatal("a route from acme's workflow to globex's channel must be refused")
		} else if !strings.Contains(err.Error(), "cross-tenant") {
			t.Fatalf("error should name the reason, got: %v", err)
		}
		// Same-tenant still works.
		if err := j.AddNotificationRoute(ctx, "wf_acme_a", acmeCh, "failed"); err != nil {
			t.Fatalf("same-tenant route must still work: %v", err)
		}
		// Unknown endpoints refused, not silently written.
		if err := j.AddNotificationRoute(ctx, "wf_acme_a", "nch_ghost", "failed"); err == nil {
			t.Fatal("a route naming a nonexistent channel must be refused")
		}
		if err := j.AddNotificationRoute(ctx, "wf_ghost", acmeCh, "failed"); err == nil {
			t.Fatal("a route naming a nonexistent workflow must be refused")
		}
	})
}

// TestRunIdentityIsAuthoritative pins the helper the secret ACL now depends on.
// It must answer from the run, and it must fail rather than return an empty
// string, so a caller cannot mistake "unknown run" for "the default tenant".
func TestRunIdentityIsAuthoritative(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_x", "shared", "h", "0.1.0", json.RawMessage(`{}`), "tenant-x"); err != nil {
		t.Fatal(err)
	}
	// A second tenant owning the SAME slug is what broke the slug-based lookup.
	if err := j.CreateWorkflowInTenant(ctx, "wf_y", "shared", "h", "0.1.0", json.RawMessage(`{}`), "tenant-y"); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateRun(ctx, "run_x", "wf_x", "manual", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Force wf_y to be strictly newer. Created in the same millisecond the two
	// timestamps tie and ORDER BY created_at DESC picks arbitrarily, which would
	// make the contrast below a coin flip rather than an assertion.
	if _, err := j.db.ExecContext(ctx,
		j.bind(`UPDATE workflows SET created_at = $1 WHERE id = $2`),
		"2099-01-01T00:00:00.000Z", "wf_y"); err != nil {
		t.Fatal(err)
	}

	wfID, tenant, err := j.RunIdentity(ctx, "run_x")
	if err != nil {
		t.Fatal(err)
	}
	if wfID != "wf_x" || tenant != "tenant-x" {
		t.Fatalf("RunIdentity = (%q, %q), want (wf_x, tenant-x)", wfID, tenant)
	}
	// The slug lookup, by contrast, answers with whichever row is newest, which
	// here is the OTHER tenant's. This is the ambiguity the ACL gate used to make
	// its decisions on: same slug, wrong workflow, wrong tenant's grants.
	slugID, err := j.WorkflowIDBySlug(ctx, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if slugID != "wf_y" {
		t.Fatalf("unscoped slug lookup returned %q, want wf_y (the newest row)", slugID)
	}
	if slugID == wfID {
		t.Fatal("the slug lookup and the run identity agreed; this test is no longer exercising the divergence")
	}

	if _, _, err := j.RunIdentity(ctx, "run_missing"); err == nil {
		t.Fatal("an unknown run must error, not return an empty tenant")
	}
	if _, _, err := j.RunIdentity(ctx, ""); err == nil {
		t.Fatal("an empty run id must error")
	}
}

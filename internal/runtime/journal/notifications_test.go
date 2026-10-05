package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestListNotificationChannelMetadataPageIsBoundedAndConfigFree(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.EnablePayloadEncryption(ctx, bytes.Repeat([]byte{0x72}, 32), nil); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ tenant, name string }{
		{"acme", "alpha"}, {"globex", "bravo"}, {"acme", "charlie"},
	} {
		if _, err := j.CreateNotificationChannelInTenant(ctx, row.tenant, row.name, ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid/hook"}`)); err != nil {
			t.Fatal(err)
		}
	}
	unkeyed := New(j.db, EngineSQLite)
	if _, err := unkeyed.ListNotificationChannels(ctx); err == nil {
		t.Fatal("full channel read unexpectedly succeeded without payload key")
	}
	first, more, err := unkeyed.ListNotificationChannelMetadataPage(ctx, 2, 0)
	if err != nil || !more || len(first) != 2 || first[0].Name != "alpha" || first[1].Name != "bravo" {
		t.Fatalf("first metadata page = %+v more=%v err=%v", first, more, err)
	}
	last, more, err := unkeyed.ListNotificationChannelMetadataPage(ctx, 2, 2)
	if err != nil || more || len(last) != 1 || last[0].Name != "charlie" {
		t.Fatalf("last metadata page = %+v more=%v err=%v", last, more, err)
	}
	if _, _, err := unkeyed.ListNotificationChannelMetadataPage(ctx, 501, 0); err == nil {
		t.Fatal("oversized metadata page accepted")
	}
}

func TestCreateNotificationChannelRejectsBadKind(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	_, err := j.CreateNotificationChannel(context.Background(), "ops", "carrier-pigeon", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("bad kind should have been rejected")
	}
}

func TestCreateNotificationChannelRoundTrip(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	id, err := j.CreateNotificationChannel(ctx, "ops-slack", "slack_webhook", json.RawMessage(`{"url":"https://hooks.slack.com/services/X/Y/Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := j.GetNotificationChannel(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Name != "ops-slack" || ch.Kind != "slack_webhook" {
		t.Fatalf("got %+v", ch)
	}
	list, err := j.ListNotificationChannels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("list = %+v", list)
	}
}

func TestListNotificationChannelMetadataPageDoesNotMaterializeConfig(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	secret := strings.Repeat("s", 2<<20)
	id, err := j.CreateNotificationChannelInTenant(ctx, "acme", "oversized", ChannelKindGenericWebhook,
		json.RawMessage(`{"url":"https://example.invalid","auth_header":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	page, hasMore, err := j.ListNotificationChannelMetadataByTenantPage(ctx, "acme", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(page) != 1 {
		t.Fatalf("metadata page = %+v has_more=%v", page, hasMore)
	}
	if page[0].ID != id || page[0].TenantID != "acme" || page[0].Name != "oversized" || page[0].Kind != ChannelKindGenericWebhook {
		t.Fatalf("metadata row = %+v", page[0])
	}
	encoded, err := json.Marshal(page[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "auth_header") || strings.Contains(string(encoded), secret) {
		t.Fatalf("metadata projection leaked config: %s", encoded)
	}
}

func TestGetNotificationChannelMetadataForTenantDoesNotMaterializeConfig(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	secret := strings.Repeat("s", 4<<20)
	id, err := j.CreateNotificationChannelInTenant(ctx, "acme", "oversized-exact", ChannelKindGenericWebhook,
		json.RawMessage(`{"url":"https://example.invalid","auth_header":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := j.GetNotificationChannelMetadataForTenant(ctx, id, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ID != id || metadata.TenantID != "acme" || metadata.Name != "oversized-exact" {
		t.Fatalf("metadata = %+v", metadata)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "auth_header") || strings.Contains(string(encoded), secret) {
		t.Fatalf("metadata projection leaked config: %s", encoded)
	}
	if _, err := j.GetNotificationChannelMetadataForTenant(ctx, id, "globex"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign tenant lookup = %v, want ErrNotFound", err)
	}
}

func TestListNotificationRoutesPageBoundedText(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	if err := j.CreateWorkflowInTenant(ctx, "wf_bounded_routes", "bounded-routes", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("n", 8192)
	id, err := j.CreateNotificationChannelInTenant(ctx, "acme", name, ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://example.invalid"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_bounded_routes", id, "failed"); err != nil {
		t.Fatal(err)
	}
	statuses := strings.Repeat("x", 4096)
	if _, err := j.db.ExecContext(ctx, j.bind(`UPDATE workflow_notification_routes SET on_statuses = $1 WHERE workflow_id = $2 AND channel_id = $3`), statuses, "wf_bounded_routes", id); err != nil {
		t.Fatal(err)
	}
	routes, err := j.ListNotificationRoutesForWorkflowPageBounded(ctx, "wf_bounded_routes", 10, 0, 128, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || !routes[0].ChannelNameTruncated || routes[0].ChannelNameBytes <= 128 || len([]byte(routes[0].ChannelName)) > 128 || !routes[0].OnStatusesTruncated || routes[0].OnStatusesBytes <= 256 || len([]byte(routes[0].OnStatuses)) > 256 {
		t.Fatalf("bounded route = %+v", routes)
	}
}

func TestNotificationRouteUpsertNormalisesStatuses(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	id, err := j.CreateNotificationChannel(ctx, "c1", "generic_webhook", json.RawMessage(`{"url":"https://x.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Statuses with weird whitespace + duplicates + uppercase.
	if err := j.AddNotificationRoute(ctx, "wf_1", id, " Failed ,FAILED_DLQ, failed "); err != nil {
		t.Fatal(err)
	}
	routes, err := j.ListNotificationRoutesForWorkflow(ctx, "wf_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %+v", routes)
	}
	want := "failed,failed_dlq"
	if routes[0].OnStatuses != want {
		t.Fatalf("on_statuses = %q, want %q", routes[0].OnStatuses, want)
	}
	// Re-add with a different shape -> upserts.
	if err := j.AddNotificationRoute(ctx, "wf_1", id, "succeeded"); err != nil {
		t.Fatal(err)
	}
	routes, _ = j.ListNotificationRoutesForWorkflow(ctx, "wf_1")
	if routes[0].OnStatuses != "succeeded" {
		t.Fatalf("upsert failed: %q", routes[0].OnStatuses)
	}
}

func TestChannelsForRunTerminalFilters(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	id, err := j.CreateNotificationChannel(ctx, "ops", "generic_webhook", json.RawMessage(`{"url":"https://x.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.AddNotificationRoute(ctx, "wf_1", id, "failed,failed_dlq"); err != nil {
		t.Fatal(err)
	}

	// failed_dlq fires.
	got, err := j.ChannelsForRunTerminal(ctx, "wf_1", "failed_dlq")
	if err != nil || len(got) != 1 {
		t.Fatalf("failed_dlq: got=%+v err=%v", got, err)
	}
	// succeeded does NOT fire under the default route.
	got, err = j.ChannelsForRunTerminal(ctx, "wf_1", "succeeded")
	if err != nil || len(got) != 0 {
		t.Fatalf("succeeded: got=%+v err=%v", got, err)
	}
	// Different workflow returns nothing.
	got, _ = j.ChannelsForRunTerminal(ctx, "wf_other", "failed")
	if len(got) != 0 {
		t.Fatalf("other workflow: %+v", got)
	}
}

func TestNotificationRouteReadsFenceLegacyCrossTenantRows(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()

	if err := j.CreateWorkflowInTenant(ctx, "wf_acme", "acme-flow", "h", "0.1.0", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	channelID, err := j.CreateNotificationChannelInTenant(ctx, "globex", "globex-ops", ChannelKindGenericWebhook, json.RawMessage(`{"url":"https://globex.example/hook"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a relation written before the tenant guard existed (or restored
	// from a legacy database). New writes reject this topology, but reads and
	// terminal delivery must still fail closed if one remains.
	if _, err := j.db.ExecContext(ctx, j.bind(`INSERT INTO workflow_notification_routes (workflow_id, channel_id, on_statuses) VALUES ($1, $2, $3)`), "wf_acme", channelID, "failed"); err != nil {
		t.Fatal(err)
	}

	if routes, err := j.ListNotificationRoutesForWorkflow(ctx, "wf_acme"); err != nil {
		t.Fatal(err)
	} else if len(routes) != 0 {
		t.Fatalf("cross-tenant route leaked through unpaged read: %+v", routes)
	}
	if routes, err := j.ListNotificationRoutesForWorkflowPage(ctx, "wf_acme", 10, 0); err != nil {
		t.Fatal(err)
	} else if len(routes) != 0 {
		t.Fatalf("cross-tenant route leaked through paged read: %+v", routes)
	}
	if channels, err := j.ChannelsForRunTerminal(ctx, "wf_acme", "failed"); err != nil {
		t.Fatal(err)
	} else if len(channels) != 0 {
		t.Fatalf("cross-tenant channel reached terminal notifier: %+v", channels)
	}
}

func TestDeleteChannelRefusesInUse(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	id, _ := j.CreateNotificationChannel(ctx, "ops", "generic_webhook", json.RawMessage(`{"url":"https://x.com"}`))
	_ = j.AddNotificationRoute(ctx, "wf_1", id, "failed")
	if err := j.DeleteNotificationChannel(ctx, id); !errors.Is(err, ErrChannelInUse) {
		t.Fatalf("err = %v, want ErrChannelInUse", err)
	}
	// Detach + delete succeeds.
	_ = j.DeleteNotificationRoute(ctx, "wf_1", id)
	if err := j.DeleteNotificationChannel(ctx, id); err != nil {
		t.Fatalf("after detach: %v", err)
	}
}

func TestDeleteWorkflowCascadesNotificationRoutes(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	id, _ := j.CreateNotificationChannel(ctx, "ops", "generic_webhook", json.RawMessage(`{"url":"https://x.com"}`))
	_ = j.AddNotificationRoute(ctx, "wf_1", id, "failed")
	// Move the seeded run terminal so DeleteWorkflow proceeds.
	if err := j.MarkRunFinished(ctx, "run_1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := j.DeleteWorkflow(ctx, "wf_1"); err != nil {
		t.Fatalf("delete workflow: %v", err)
	}
	routes, _ := j.ListNotificationRoutesForWorkflow(ctx, "wf_1")
	if len(routes) != 0 {
		t.Fatalf("routes survived cascade: %+v", routes)
	}
	// Channel itself stays (only the route was tied to the workflow).
	if _, err := j.GetNotificationChannel(ctx, id); err != nil {
		t.Fatalf("channel should still exist: %v", err)
	}
}

func TestAddRouteRejectsEmptyStatuses(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	id, _ := j.CreateNotificationChannel(ctx, "ops", "generic_webhook", json.RawMessage(`{"url":"https://x.com"}`))
	if err := j.AddNotificationRoute(ctx, "wf_1", id, "  ,, "); err == nil || !strings.Contains(err.Error(), "on_statuses") {
		t.Fatalf("empty on_statuses should have been rejected, got %v", err)
	}
}

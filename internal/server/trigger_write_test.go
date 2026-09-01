package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

func TestWebhookTriggerFormOffersAutomationV1(t *testing.T) {
	t.Parallel()
	html := renderAddTriggerSection("sales-partner-signing", "")
	if !strings.Contains(html, `<option value="automation-v1">`) {
		t.Fatal("webhook trigger form does not offer automation-v1")
	}
	if !strings.Contains(html, `<option value="hash-v1">`) {
		t.Fatal("webhook trigger form does not offer hash-v1")
	}
	if !strings.Contains(html, "64-character HMAC key") || !strings.Contains(html, "do not hex-decode") {
		t.Fatal("webhook trigger form does not explain how to use the displayed HMAC key")
	}
}

func TestWebhookProviderPinnedByDAG(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dag  string
		want string
		err  string
	}{
		{name: "no triggers", dag: `{}`, want: ""},
		{name: "cron only", dag: `{"triggers":[{"kind":"cron"}]}`, want: ""},
		{name: "legacy webhook without provider", dag: `{"triggers":[{"kind":"webhook"}]}`, want: ""},
		{name: "automation", dag: `{"triggers":[{"kind":"webhook","provider":"automation-v1"}]}`, want: "automation-v1"},
		{name: "same provider repeated", dag: `{"triggers":[{"kind":"webhook","provider":"github"},{"kind":"webhook","provider":"github"}]}`, want: "github"},
		{name: "conflict", dag: `{"triggers":[{"kind":"webhook","provider":"generic"},{"kind":"webhook","provider":"automation-v1"}]}`, err: "conflicting"},
		{name: "unsupported", dag: `{"triggers":[{"kind":"webhook","provider":"made-up"}]}`, err: "unsupported"},
		{name: "provider whitespace", dag: `{"triggers":[{"kind":"webhook","provider":" automation-v1"}]}`, err: "whitespace"},
		{name: "bad json", dag: `{`, err: "parse"},
		{name: "non object", dag: `[]`, err: "unmarshal"},
		{name: "null", dag: `null`, err: "object"},
		{name: "bad trigger", dag: `{"triggers":[5]}`, err: "parse triggers"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := webhookProviderPinnedByDAG(json.RawMessage(tc.dag))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("got (%q, %v), want error containing %q", got, err, tc.err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
}

func TestAutomationV1TriggerCannotChangeReceiptProtocolToSync(t *testing.T) {
	t.Parallel()
	if err := validateWebhookTriggerMode(webhook.ProviderAutomationV1, true); err == nil {
		t.Fatal("automation-v1 synchronous trigger was accepted")
	}
	if err := validateWebhookTriggerMode(webhook.ProviderAutomationV1, false); err != nil {
		t.Fatalf("automation-v1 async trigger rejected: %v", err)
	}
	if err := validateWebhookTriggerMode(webhook.ProviderHashV1, true); err == nil {
		t.Fatal("hash-v1 synchronous trigger was accepted")
	}
	if err := validateWebhookTriggerMode(webhook.ProviderHashV1, false); err != nil {
		t.Fatalf("hash-v1 async trigger rejected: %v", err)
	}
	if err := validateWebhookTriggerMode("generic", true); err != nil {
		t.Fatalf("generic sync trigger rejected: %v", err)
	}
}

func TestHashV1CreationInstructionsSignTimestampAndExactBody(t *testing.T) {
	t.Parallel()
	html := renderTriggersSection(workflowDetailData{
		NewWebhookToken:        "whk_test",
		NewWebhookSecret:       "secret-test-value",
		NewWebhookProvider:     webhook.ProviderHashV1,
		NewWebhookCredentialID: "webhook_hash_001",
	})
	for _, want := range []string{
		`BODY='{"event_id":"5fbf907a-3900-4b9f-951c-3bd07632728c","kind":"document.completed","occurred_at":"2026-09-01T12:00:00Z","org_id":"be6d7557-fd3c-4b8d-a0ce-8f0d834e910c","automation_request_id":"ed452068-8faa-44ef-968f-a34027eb8b6e","document":{"id":"09bc3de6-931a-4b7c-a3ec-07f6fd8b103b"}}'`,
		`TIMESTAMP=$(date +%s)`,
		`printf '%s.%s' "$TIMESTAMP" "$BODY"`,
		`X-Hash-Signature: t=$TIMESTAMP,v1=$SIG`,
		`--data-binary "$BODY"`,
		`use it verbatim and do not hex-decode it`,
		`href="/credentials/webhook_hash_001#manual-update"`,
		`Hash does not adopt it`,
		`Manual update`,
		`exact 64 ASCII-hex bytes`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("hash-v1 creation instructions missing %q\n%s", want, html)
		}
	}
	for _, forbidden := range []string{`"type":`, `"document_id":`, `/credentials/secret-test-value`} {
		if strings.Contains(html, forbidden) {
			t.Errorf("hash-v1 creation instructions contain obsolete or secret-bearing value %q\n%s", forbidden, html)
		}
	}
}

func TestWebhookCredentialIDIsNotRenderedOutsideOneTimeCreationResult(t *testing.T) {
	t.Parallel()
	const credentialID = "webhook_must_remain_hidden"
	html := renderTriggersSection(workflowDetailData{
		NewWebhookCredentialID: credentialID,
		Triggers: []journal.Trigger{{
			ID:       "trg_one",
			Kind:     journal.TriggerWebhook,
			State:    "active",
			TokenID:  "whk_public",
			SecretID: credentialID,
			Provider: webhook.ProviderHashV1,
		}},
	})
	if strings.Contains(html, credentialID) {
		t.Fatalf("persistent trigger rendering exposed backing credential ID: %s", html)
	}
}

func TestAutomationV1CreationInstructionsBindTimestampDeliveryAndBody(t *testing.T) {
	t.Parallel()
	html := renderTriggersSection(workflowDetailData{
		NewWebhookToken:    "whk_test",
		NewWebhookSecret:   "secret-test-value",
		NewWebhookProvider: webhook.ProviderAutomationV1,
	})
	for _, want := range []string{
		`TIMESTAMP=$(date +%s)`,
		`printf '%s.%s.%s' "$TIMESTAMP" "$DELIVERY" "$BODY"`,
		`X-Webhook-Timestamp: $TIMESTAMP`,
		`X-Webhook-Delivery: $DELIVERY`,
		`X-Webhook-Signature: sha256=$SIG`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("automation-v1 creation instructions missing %q", want)
		}
	}
}

type triggerTestEnv struct {
	server  *httptest.Server
	s       *Server
	db      *sql.DB
	j       *journal.Journal
	repo    *credentials.Repo
	store   *vault.Store
	backend *vault.MemoryBackend
}

func newTriggerTestEnv(t *testing.T) triggerTestEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "trigger.db")
	dbURL := "sqlite://" + dbPath
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), log, dbURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	j := journal.New(db, journal.EngineSQLite)
	repo := credentials.New(db, credentials.EngineSQLite)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	backend := vault.NewMemoryBackend()
	store, err := vault.NewStore(backend, masterKey)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	s := &Server{
		Journal: j, Credentials: repo, Vault: store, Log: log,
		Registry: registry.New(filepath.Join(t.TempDir(), "workflows")),
		flash:    newFlashStore(),
	}
	router := chi.NewRouter()
	router.Get("/workflows/{slug}", s.workflowDetail)
	router.Post("/workflows/{slug}/triggers", s.workflowCreateTrigger)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return triggerTestEnv{server: server, s: s, db: db, j: j, repo: repo, store: store, backend: backend}
}

func TestWebhookTriggerCreationUsesSelectedWorkflowTenantWithDuplicateSlug(t *testing.T) {
	t.Parallel()
	env := newTriggerTestEnv(t)
	ctx := context.Background()
	if err := env.j.CreateWorkflowInTenant(ctx, "wf_acme", "shared", "h", "1", json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"automation-v1"}]}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := env.j.CreateWorkflowInTenant(ctx, "wf_globex", "shared", "h", "1", json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"generic"}]}`), "globex"); err != nil {
		t.Fatal(err)
	}
	pageResp, err := http.Get(env.server.URL + "/workflows/shared?tenant=acme")
	if err != nil {
		t.Fatal(err)
	}
	pageBody, readErr := io.ReadAll(pageResp.Body)
	_ = pageResp.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if pageResp.StatusCode != http.StatusOK || !strings.Contains(string(pageBody), `action="/workflows/shared/triggers?tenant=acme"`) {
		t.Fatalf("tenant-scoped trigger form missing (status %d): %s", pageResp.StatusCode, pageBody)
	}

	resp := postSameOrigin(t, env.server.URL+"/workflows/shared/triggers?tenant=acme", url.Values{
		"kind":     {"webhook"},
		"provider": {"automation-v1"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 303: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "/workflows/shared?tenant=acme" {
		t.Fatalf("Location = %q, want tenant-scoped workflow URL", got)
	}

	acmeTriggers, err := env.j.ListTriggersForWorkflow(ctx, "wf_acme")
	if err != nil || len(acmeTriggers) != 1 {
		t.Fatalf("acme triggers = %+v, %v", acmeTriggers, err)
	}
	if acmeTriggers[0].TenantID != "acme" || acmeTriggers[0].Provider != webhook.ProviderAutomationV1 {
		t.Fatalf("acme trigger = %+v", acmeTriggers[0])
	}
	globexTriggers, err := env.j.ListTriggersForWorkflow(ctx, "wf_globex")
	if err != nil || len(globexTriggers) != 0 {
		t.Fatalf("globex triggers = %+v, %v", globexTriggers, err)
	}
	credential, err := env.repo.Get(ctx, acmeTriggers[0].SecretID)
	if err != nil {
		t.Fatal(err)
	}
	if credential.TenantID != "acme" {
		t.Fatalf("credential tenant = %q, want acme", credential.TenantID)
	}
	flashCookies := resp.Cookies()
	if len(flashCookies) != 1 {
		t.Fatalf("flash cookie count = %d, want 1", len(flashCookies))
	}
	flashReq := httptest.NewRequest(http.MethodGet, "/workflows/shared?tenant=acme", nil)
	flashReq.AddCookie(flashCookies[0])
	flashPayload := env.s.flash.take(httptest.NewRecorder(), flashReq)
	if got := flashPayload["new_webhook_credential_id"]; got != acmeTriggers[0].SecretID {
		t.Fatalf("one-time credential ID = %q, want %q", got, acmeTriggers[0].SecretID)
	}
	if strings.Contains(resp.Header.Get("Location"), acmeTriggers[0].SecretID) ||
		strings.Contains(resp.Header.Get("Location"), flashPayload["new_webhook_secret"]) {
		t.Fatalf("redirect leaked credential material: %q", resp.Header.Get("Location"))
	}
}

func TestWebhookTriggerCreationRejectsProviderDowngradeBeforeSideEffects(t *testing.T) {
	t.Parallel()
	env := newTriggerTestEnv(t)
	ctx := context.Background()
	if err := env.j.CreateWorkflowInTenant(ctx, "wf_hash", "hash-bridge", "h", "1", json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"automation-v1"}]}`), "acme"); err != nil {
		t.Fatal(err)
	}

	resp := postSameOrigin(t, env.server.URL+"/workflows/hash-bridge/triggers?tenant=acme", url.Values{
		"kind":     {"webhook"},
		"provider": {"generic"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400: %s", resp.StatusCode, body)
	}
	if triggers, err := env.j.ListTriggersForWorkflow(ctx, "wf_hash"); err != nil || len(triggers) != 0 {
		t.Fatalf("trigger side effect after rejected downgrade: %+v, %v", triggers, err)
	}
	if creds, err := env.repo.List(ctx); err != nil || len(creds) != 0 {
		t.Fatalf("credential side effect after rejected downgrade: %+v, %v", creds, err)
	}
}

func TestWebhookTriggerCreationRollsBackCredentialWhenJournalInsertFails(t *testing.T) {
	t.Parallel()
	env := newTriggerTestEnv(t)
	ctx := context.Background()
	if err := env.j.CreateWorkflowInTenant(ctx, "wf_acme", "insert-failure", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.ExecContext(ctx, `DROP TABLE triggers`); err != nil {
		t.Fatal(err)
	}

	resp := postSameOrigin(t, env.server.URL+"/workflows/insert-failure/triggers?tenant=acme", url.Values{
		"kind":     {"webhook"},
		"provider": {"generic"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 500: %s", resp.StatusCode, body)
	}
	if creds, err := env.repo.List(ctx); err != nil || len(creds) != 0 {
		t.Fatalf("credential was not compensated: %+v, %v", creds, err)
	}
	if ids, err := env.backend.List(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("vault secret was not compensated: %+v, %v", ids, err)
	}
}

func TestRollbackWebhookTriggerSetupRemovesTriggerSecretAndCredential(t *testing.T) {
	t.Parallel()
	env := newTriggerTestEnv(t)
	ctx := context.Background()
	if err := env.j.CreateWorkflowInTenant(ctx, "wf_acme", "rollback", "h", "1", json.RawMessage(`{}`), "acme"); err != nil {
		t.Fatal(err)
	}
	if err := env.repo.Create(ctx, credentials.CreateParams{ID: "cred_rollback", Name: "cred_rollback", TenantID: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Put(ctx, "cred_rollback", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	triggerID, err := env.j.CreateWebhookTrigger(ctx, "wf_acme", "whk_rollback", "cred_rollback", "generic", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.s.rollbackWebhookTriggerSetup(ctx, triggerID, "cred_rollback"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if triggers, err := env.j.ListTriggersForWorkflow(ctx, "wf_acme"); err != nil || len(triggers) != 0 {
		t.Fatalf("triggers after rollback = %+v, %v", triggers, err)
	}
	if _, err := env.repo.Get(ctx, "cred_rollback"); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatalf("credential after rollback: %v", err)
	}
	if _, err := env.store.Get(ctx, "cred_rollback"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("vault secret after rollback: %v", err)
	}
}

func TestTriggerFormsPreserveAdminTenantQuery(t *testing.T) {
	t.Parallel()
	html := renderTriggersSection(workflowDetailData{
		Slug:                 "shared",
		TriggerWritesEnabled: true,
		TriggerActionQuery:   "?tenant=acme",
		Triggers: []journal.Trigger{{
			ID:    "trg_one",
			Kind:  journal.TriggerCron,
			State: "active",
		}},
	})
	for _, want := range []string{
		`action="/workflows/shared/triggers?tenant=acme"`,
		`action="/workflows/shared/triggers/trg_one/pause?tenant=acme"`,
		`action="/workflows/shared/triggers/trg_one/delete?tenant=acme"`,
		`action="/workflows/shared/triggers/trg_one/edit?tenant=acme"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("trigger HTML missing %s", want)
		}
	}
}

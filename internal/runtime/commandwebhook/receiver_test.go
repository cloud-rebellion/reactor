package commandwebhook_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/commandrunner"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/commandwebhook"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

const commandWebhookTestSecret = "command-webhook-test-secret"

type commandWebhookHarness struct {
	db         *sql.DB
	journal    *journal.Journal
	queue      *commandrunner.Queue
	receiver   *commandwebhook.Receiver
	sandbox    *commandWebhookSandbox
	trigger    journal.CommandAutomationWebhookTrigger
	secret     *testVault
	plan       journal.CommandAutomation
	definition commandautomations.Definition
}

func newCommandWebhookHarness(t *testing.T, tenant string) *commandWebhookHarness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "command-webhook.db")
	testLog := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(ctx, testLog, "sqlite://"+dbPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	j := journal.New(db, journal.EngineSQLite)
	creds := credentials.New(db, credentials.EngineSQLite)
	if err := creds.Create(ctx, credentials.CreateParams{
		ID: "cred_command_webhook_" + tenant, Name: "command webhook", TenantID: tenant,
		Service: "reactor-webhook", Provider: "shared-secret",
	}); err != nil {
		db.Close()
		t.Fatalf("create webhook credential: %v", err)
	}

	raw := []byte(`{"steps":[{"name":"check","command":"true","purpose":"Check","timeout_seconds":1,"expected_exit_code":0}]}`)
	definition, normalized, err := commandautomations.Normalize(raw)
	if err != nil {
		db.Close()
		t.Fatalf("normalize definition: %v", err)
	}
	plan, err := j.CreateCommandAutomation(ctx, tenant, "cmd_webhook_ingress_"+tenant, "webhook-ingress", "", "local", "alice", normalized)
	if err != nil {
		db.Close()
		t.Fatalf("create command automation: %v", err)
	}
	if err := j.SetCommandAutomationEnabledIfStateAndVersion(ctx, tenant, plan.ID, true, false, plan.CurrentVersion); err != nil {
		db.Close()
		t.Fatalf("enable command automation: %v", err)
	}
	digest := sha256.Sum256(normalized)
	digestHex := hex.EncodeToString(digest[:])
	// The runner marks trigger authorization and the durable plan state at
	// admission, so the trigger's receipt must be minted from those exact facts.
	caps := commandautomations.ExecutionCapabilities{
		FeatureEnabled: true, SingleTenant: true, TriggerAuthorized: true,
		AutomationEnabled: true, SandboxProfileReady: true, VaultBoundaryReady: true,
		CredentialsSupported: true, OutputLimitsReady: true, AuditReady: true,
		RunnerReady: true, TargetReady: true,
	}
	receipt := commandautomations.EvaluateExecutionGates(definition, caps)
	binding := commandautomations.BindExecutionReceipt(tenant, plan.ID, plan.CurrentVersion, digestHex, receipt)
	triggerInput := journal.CommandAutomationWebhookTriggerInput{
		ID: "cmdwhk_trigger_" + tenant, AutomationID: plan.ID, AutomationVersion: plan.CurrentVersion,
		DefinitionSHA256: digestHex, ReceiptID: binding.ReceiptID, GateDigest: binding.GateDigest,
		ActorID: "alice", TokenID: "cmdwhk_token_" + tenant, SecretID: "cred_command_webhook_" + tenant,
		Provider: "generic",
	}
	trigger, err := j.CreateCommandAutomationWebhookTrigger(ctx, tenant, triggerInput)
	if err != nil {
		db.Close()
		t.Fatalf("create command webhook trigger: %v", err)
	}
	if err := j.SetCommandAutomationWebhookTriggerStateIfRevision(ctx, tenant, trigger.ID, journal.CommandAutomationWebhookActive, trigger.Revision); err != nil {
		db.Close()
		t.Fatalf("activate command webhook trigger: %v", err)
	}
	trigger, err = j.GetCommandAutomationWebhookTriggerForTenant(ctx, tenant, trigger.ID)
	if err != nil {
		db.Close()
		t.Fatalf("reload command webhook trigger: %v", err)
	}

	sandbox := &commandWebhookSandbox{}
	runner := &commandrunner.Runner{
		Journal: j, Sandbox: sandbox, Enabled: true,
		TargetPolicy: commandrunner.ExactTargetPolicy{"local": {}},
		ScheduledCapabilitiesProvider: func(context.Context, commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			return commandautomations.ExecutionCapabilities{
				FeatureEnabled: true, SingleTenant: true, SandboxProfileReady: true,
				VaultBoundaryReady: true, CredentialsSupported: true, OutputLimitsReady: true,
				AuditReady: true, RunnerReady: true,
			}, nil
		},
	}
	queue, err := commandrunner.NewQueue(runner, j, commandrunner.QueueConfig{
		Workers: 1, Capacity: 1, PollInterval: 10 * time.Millisecond, TenantID: tenant, WorkerPrefix: "command-webhook-test",
	})
	if err != nil {
		db.Close()
		t.Fatalf("new command queue: %v", err)
	}
	if err := queue.Start(ctx); err != nil {
		db.Close()
		t.Fatalf("start command queue: %v", err)
	}
	secret := &testVault{value: []byte(commandWebhookTestSecret)}
	receiver := &commandwebhook.Receiver{
		Journal: j, Vault: secret, Runner: runner, Queue: queue, TenantID: tenant,
		Log: testLog,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	h := &commandWebhookHarness{db: db, journal: j, queue: queue, receiver: receiver, sandbox: sandbox, trigger: trigger, secret: secret, plan: plan, definition: definition}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := queue.Stop(stopCtx); err != nil {
			t.Errorf("stop command queue: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Errorf("close command webhook db: %v", err)
		}
	})
	return h
}

func TestReceiverAdmitsSignedDeliveryAndDeduplicates(t *testing.T) {
	t.Parallel()
	h := newCommandWebhookHarness(t, "acme")
	router := chi.NewRouter()
	h.receiver.Mount(router)
	body := []byte(`{"event":"reconcile","value":"untrusted input"}`)
	deliveryID := "delivery-command-1"

	// Authentication failure must not create a durable run or claim a delivery.
	bad := httptest.NewRequest(http.MethodPost, "/command-webhook/"+h.trigger.TokenID, bytes.NewReader(body))
	bad.Header.Set("X-Webhook-Delivery", deliveryID+"-bad")
	bad.Header.Set("X-Webhook-Signature", "sha256="+signCommandWebhook([]byte("wrong"), body))
	badRec := httptest.NewRecorder()
	router.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status = %d, want %d", badRec.Code, http.StatusUnauthorized)
	}

	first := signedCommandWebhookRequest(h.trigger.TokenID, body, deliveryID, []byte(commandWebhookTestSecret))
	firstRec := httptest.NewRecorder()
	router.ServeHTTP(firstRec, first)
	if firstRec.Code != http.StatusAccepted {
		t.Fatalf("first delivery status = %d body=%s, want %d", firstRec.Code, firstRec.Body.String(), http.StatusAccepted)
	}
	if got := firstRec.Header().Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Fatalf("command webhook receipt Cache-Control = %q, want no-store", got)
	}
	if got := firstRec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("command webhook receipt Pragma = %q, want no-cache", got)
	}
	var firstReceipt struct {
		Accepted bool   `json:"accepted"`
		Deduped  bool   `json:"deduped"`
		RunID    string `json:"run_id"`
	}
	if err := json.NewDecoder(firstRec.Body).Decode(&firstReceipt); err != nil {
		t.Fatalf("decode first receipt: %v", err)
	}
	if !firstReceipt.Accepted || firstReceipt.Deduped || firstReceipt.RunID == "" {
		t.Fatalf("first receipt = %+v", firstReceipt)
	}

	run := waitForCommandRun(t, h.journal, "acme", firstReceipt.RunID)
	if run.Status != journal.CommandRunSucceeded {
		t.Fatalf("run status = %q, want %q (error=%q)", run.Status, journal.CommandRunSucceeded, run.ErrorText)
	}
	h.sandbox.mu.Lock()
	calls := h.sandbox.calls
	h.sandbox.mu.Unlock()
	if calls != 1 {
		t.Fatalf("sandbox calls = %d, want 1", calls)
	}

	// The same authenticated delivery is a durable replay receipt and must not
	// reclaim or execute the command again.
	second := signedCommandWebhookRequest(h.trigger.TokenID, body, deliveryID, []byte(commandWebhookTestSecret))
	secondRec := httptest.NewRecorder()
	router.ServeHTTP(secondRec, second)
	if secondRec.Code != http.StatusOK {
		t.Fatalf("duplicate delivery status = %d body=%s, want %d", secondRec.Code, secondRec.Body.String(), http.StatusOK)
	}
	var secondReceipt struct {
		Accepted bool   `json:"accepted"`
		Deduped  bool   `json:"deduped"`
		RunID    string `json:"run_id"`
	}
	if err := json.NewDecoder(secondRec.Body).Decode(&secondReceipt); err != nil {
		t.Fatalf("decode duplicate receipt: %v", err)
	}
	if !secondReceipt.Accepted || !secondReceipt.Deduped || secondReceipt.RunID != firstReceipt.RunID {
		t.Fatalf("duplicate receipt = %+v, want same deduped run", secondReceipt)
	}
	h.sandbox.mu.Lock()
	calls = h.sandbox.calls
	h.sandbox.mu.Unlock()
	if calls != 1 {
		t.Fatalf("sandbox calls after duplicate = %d, want 1", calls)
	}

	// Generic delivery headers are not covered by the body HMAC. Command
	// ingress therefore binds identity to the authenticated body so changing
	// X-Webhook-Delivery cannot mint a second command run from one replayed
	// signed payload.
	unsignedHeaderReplay := signedCommandWebhookRequest(h.trigger.TokenID, body, "delivery-command-forged", []byte(commandWebhookTestSecret))
	unsignedHeaderReplayRec := httptest.NewRecorder()
	router.ServeHTTP(unsignedHeaderReplayRec, unsignedHeaderReplay)
	if unsignedHeaderReplayRec.Code != http.StatusOK {
		t.Fatalf("changed unsigned delivery header status = %d body=%s, want %d", unsignedHeaderReplayRec.Code, unsignedHeaderReplayRec.Body.String(), http.StatusOK)
	}
	var unsignedHeaderReceipt struct {
		Accepted bool   `json:"accepted"`
		Deduped  bool   `json:"deduped"`
		RunID    string `json:"run_id"`
	}
	if err := json.NewDecoder(unsignedHeaderReplayRec.Body).Decode(&unsignedHeaderReceipt); err != nil {
		t.Fatalf("decode changed-header receipt: %v", err)
	}
	if !unsignedHeaderReceipt.Accepted || !unsignedHeaderReceipt.Deduped || unsignedHeaderReceipt.RunID != firstReceipt.RunID {
		t.Fatalf("changed-header receipt = %+v, want deduped original run", unsignedHeaderReceipt)
	}
	h.sandbox.mu.Lock()
	calls = h.sandbox.calls
	h.sandbox.mu.Unlock()
	if calls != 1 {
		t.Fatalf("sandbox calls after changed-header replay = %d, want 1", calls)
	}

	// A receiver configured for another tenant must not expose or dispatch an
	// otherwise valid token from this tenant.
	foreignReceiver := *h.receiver
	foreignReceiver.TenantID = "other"
	foreignRouter := chi.NewRouter()
	foreignReceiver.Mount(foreignRouter)
	foreign := signedCommandWebhookRequest(h.trigger.TokenID, body, "delivery-foreign-tenant", []byte(commandWebhookTestSecret))
	foreignRec := httptest.NewRecorder()
	foreignRouter.ServeHTTP(foreignRec, foreign)
	if foreignRec.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant status = %d body=%s, want %d", foreignRec.Code, foreignRec.Body.String(), http.StatusNotFound)
	}
}

func TestReceiverDoesNotExposeDisabledTrigger(t *testing.T) {
	t.Parallel()
	h := newCommandWebhookHarness(t, "acme-disabled")
	ctx := context.Background()
	input := journal.CommandAutomationWebhookTriggerInput{
		ID: "cmdwhk_disabled_trigger", AutomationID: h.plan.ID, AutomationVersion: h.plan.CurrentVersion,
		DefinitionSHA256: h.trigger.DefinitionSHA256, ReceiptID: h.trigger.ReceiptID, GateDigest: h.trigger.GateDigest,
		ActorID: h.trigger.ActorID, TokenID: "cmdwhk_disabled_token", SecretID: h.trigger.SecretID, Provider: "generic",
	}
	disabled, err := h.journal.CreateCommandAutomationWebhookTrigger(ctx, h.trigger.TenantID, input)
	if err != nil {
		t.Fatalf("create disabled trigger: %v", err)
	}
	router := chi.NewRouter()
	h.receiver.Mount(router)
	body := []byte(`{"event":"disabled"}`)
	req := signedCommandWebhookRequest(disabled.TokenID, body, "delivery-disabled", []byte(commandWebhookTestSecret))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled trigger status = %d body=%s, want %d", rec.Code, rec.Body.String(), http.StatusNotFound)
	}
}

func signedCommandWebhookRequest(token string, body []byte, deliveryID string, secret []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/command-webhook/"+token, bytes.NewReader(body))
	req.Header.Set("X-Webhook-Delivery", deliveryID)
	req.Header.Set("X-Webhook-Signature", "sha256="+signCommandWebhook(secret, body))
	return req
}

func signCommandWebhook(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func waitForCommandRun(t *testing.T, j *journal.Journal, tenant, runID string) journal.CommandRun {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		run, err := j.GetCommandRunForTenant(context.Background(), tenant, runID)
		if err == nil && (run.Status == journal.CommandRunSucceeded || run.Status == journal.CommandRunFailed || run.Status == journal.CommandRunCancelled) {
			return run
		}
		if err != nil && !errors.Is(err, journal.ErrNotFound) {
			t.Fatalf("read command run %q: %v", runID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("command run %q did not reach a terminal state", runID)
	return journal.CommandRun{}
}

type testVault struct {
	value []byte
}

func (v *testVault) Get(context.Context, string) (*vault.Secret, error) {
	return vault.NewSecret(v.value), nil
}

type commandWebhookSandbox struct {
	mu    sync.Mutex
	calls int
}

func (*commandWebhookSandbox) Profile() commandrunner.SandboxProfile {
	return commandrunner.SandboxProfile{
		Name: "command-webhook-test", NonRoot: true, NoHostMounts: true,
		NetworkDisabled: true, ReadOnlyRoot: true, ResourceLimited: true,
		MaxOutputBytes: 1024,
	}
}

func (s *commandWebhookSandbox) Execute(context.Context, commandrunner.SandboxRequest) (commandrunner.SandboxResult, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return commandrunner.SandboxResult{ExitCode: 0, Stdout: []byte("ok")}, nil
}

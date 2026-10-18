package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/vault"
)

type flareVaultFunc func(context.Context, string) (*vault.Secret, error)

func (f flareVaultFunc) Get(ctx context.Context, id string) (*vault.Secret, error) { return f(ctx, id) }

const flareV1TestBody = `{"schema":"flare.automation.v1","event":"new_issue","project_id":"project-1","issue_id":"issue-1","event_count":3,"observed_at":"2023-11-14T22:13:20Z"}`

func configureFlareV1Trigger(t *testing.T, j *journal.Journal, token, config string) journal.Trigger {
	t.Helper()
	trigger, err := j.FindWebhookByToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.UpdateTriggerConfig(context.Background(), trigger.ID, []byte(config)); err != nil {
		t.Fatal(err)
	}
	return trigger
}

func flareV1Request(token, timestamp, event string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/webhook/flare/"+token, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Flare-Automation-Timestamp", timestamp)
	req.Header.Set("X-Flare-Automation-Event", event)
	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	req.Header.Set("X-Flare-Automation-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return req
}

func TestFlareV1FixedSenderVector(t *testing.T) {
	t.Parallel()
	header := make(http.Header)
	header.Set("X-Flare-Automation-Timestamp", "1700000000")
	header.Set("X-Flare-Automation-Signature", "sha256=ce3f18488fa034f805de9e95372014d976044bc99b6e5391f95be4279958470d")
	header.Set("X-Flare-Automation-Event", "new_issue")
	if err := verifyFlareV1(header, []byte(flareV1TestBody), []byte("test-secret"), time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("Flare sender vector rejected: %v", err)
	}
	if err := validateFlareV1Notice([]byte(flareV1TestBody), header, []byte(`{"flare_project_id":"project-1"}`)); err != nil {
		t.Fatalf("Flare notice rejected: %v", err)
	}
}

func TestPublicFlareRouteBindsStoredTriggerProvider(t *testing.T) {
	t.Run("flare notice", func(t *testing.T) {
		r, dispatched, j, token := newTestReceiverForProvider(t, "test-secret", ProviderFlareV1)
		configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1"}`)
		router := chi.NewRouter()
		r.Mount(router)
		timestamp := strconv.FormatInt(r.now().Unix(), 10)
		testBody := []byte(strings.Replace(flareV1TestBody, `"event":"new_issue"`, `"event":"test"`, 1))
		testReq := flareV1Request(token, timestamp, "test", testBody)
		testReq.URL.Path = "/webhook/flare/" + token
		testResult := httptest.NewRecorder()
		router.ServeHTTP(testResult, testReq)
		if testResult.Code != http.StatusOK || dispatched.calls.Load() != 0 {
			t.Fatalf("public channel test = %d, dispatches %d", testResult.Code, dispatched.calls.Load())
		}
		unsignedReq := flareV1Request(token, timestamp, "new_issue", []byte(flareV1TestBody))
		unsignedReq.URL.Path = "/webhook/flare/" + token
		unsignedReq.Header.Del("X-Flare-Automation-Signature")
		unsignedResult := httptest.NewRecorder()
		router.ServeHTTP(unsignedResult, unsignedReq)
		if unsignedResult.Code != http.StatusUnauthorized || dispatched.calls.Load() != 0 {
			t.Fatalf("unsigned public notice = %d, dispatches %d", unsignedResult.Code, dispatched.calls.Load())
		}
		realReq := flareV1Request(token, timestamp, "new_issue", []byte(flareV1TestBody))
		realReq.URL.Path = "/webhook/flare/" + token
		realResult := httptest.NewRecorder()
		router.ServeHTTP(realResult, realReq)
		if realResult.Code != http.StatusAccepted || dispatched.calls.Load() != 1 {
			t.Fatalf("public Flare delivery = %d, dispatches %d", realResult.Code, dispatched.calls.Load())
		}
	})

	t.Run("other provider remains private", func(t *testing.T) {
		r, dispatched, _, token := newTestReceiverForProvider(t, "test-secret", "generic")
		router := chi.NewRouter()
		r.Mount(router)
		body := []byte(`{"event_id":"generic-1"}`)
		mac := hmac.New(sha256.New, []byte("test-secret"))
		mac.Write(body)
		signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		request := func(path string) *http.Request {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			req.Header.Set("X-Webhook-Signature", signature)
			return req
		}
		publicResult := httptest.NewRecorder()
		router.ServeHTTP(publicResult, request("/webhook/flare/"+token))
		if publicResult.Code != http.StatusNotFound || dispatched.calls.Load() != 0 {
			t.Fatalf("other provider on public path = %d, dispatches %d", publicResult.Code, dispatched.calls.Load())
		}
		privateResult := httptest.NewRecorder()
		router.ServeHTTP(privateResult, request("/webhook/"+token))
		if privateResult.Code != http.StatusAccepted || dispatched.calls.Load() != 1 {
			t.Fatalf("generic private delivery = %d, dispatches %d", privateResult.Code, dispatched.calls.Load())
		}
	})
}

func TestFlareV1RejectsEmptySigningKey(t *testing.T) {
	t.Parallel()
	header := make(http.Header)
	header.Set("X-Flare-Automation-Timestamp", "1700000000")
	mac := hmac.New(sha256.New, nil)
	mac.Write([]byte("1700000000."))
	mac.Write([]byte(flareV1TestBody))
	header.Set("X-Flare-Automation-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	if err := verifyFlareV1(header, []byte(flareV1TestBody), nil, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("empty signing key accepted a valid empty-key HMAC")
	}
}

func TestFlareV1DurableAsyncDeliveryAndExactReplay(t *testing.T) {
	r, dispatched, j, token := newTestReceiverForProvider(t, "test-secret", ProviderFlareV1)
	trigger := configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1"}`)
	router := chi.NewRouter()
	r.Mount(router)
	timestamp := strconv.FormatInt(r.now().Unix(), 10)
	body := []byte(flareV1TestBody)
	request := func() *http.Request { return flareV1Request(token, timestamp, "new_issue", body) }

	first := httptest.NewRecorder()
	router.ServeHTTP(first, request())
	if first.Code != http.StatusAccepted || dispatched.asyncCalls.Load() != 1 || dispatched.syncCalls.Load() != 0 ||
		!bytes.Equal(dispatched.last, body) {
		t.Fatalf("first delivery = status %d, async %d, sync %d, body %q", first.Code,
			dispatched.asyncCalls.Load(), dispatched.syncCalls.Load(), dispatched.last)
	}
	var receipt deliveryReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &receipt); err != nil || !receipt.Accepted || receipt.RunID != "run_async" {
		t.Fatalf("first receipt = %+v, %v", receipt, err)
	}
	claim, err := j.ClaimWebhookDelivery(context.Background(), trigger.ID, ProviderFlareV1,
		sha256Hex(body), hashPayload(body), r.now(), time.Minute)
	if err != nil || claim.State != journal.WebhookDeliveryCompleted || claim.RunID != "run_async" {
		t.Fatalf("durable delivery = %+v, %v", claim, err)
	}

	second := httptest.NewRecorder()
	router.ServeHTTP(second, request())
	if second.Code != http.StatusOK || dispatched.calls.Load() != 1 {
		t.Fatalf("replay = status %d, dispatches %d", second.Code, dispatched.calls.Load())
	}
	if err := json.Unmarshal(second.Body.Bytes(), &receipt); err != nil || !receipt.Deduped || receipt.RunID != "run_async" {
		t.Fatalf("replay receipt = %+v, %v", receipt, err)
	}
}

func TestFlareV1TestNoticeDoesNotStartWorkflow(t *testing.T) {
	r, dispatched, j, token := newTestReceiverForProvider(t, "test-secret", ProviderFlareV1)
	configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1"}`)
	router := chi.NewRouter()
	r.Mount(router)
	body := []byte(strings.Replace(flareV1TestBody, `"event":"new_issue"`, `"event":"test"`, 1))
	req := flareV1Request(token, strconv.FormatInt(r.now().Unix(), 10), "test", body)
	result := httptest.NewRecorder()
	router.ServeHTTP(result, req)
	if result.Code != http.StatusOK || dispatched.calls.Load() != 0 {
		t.Fatalf("test delivery = status %d, dispatches %d", result.Code, dispatched.calls.Load())
	}
	var response map[string]any
	if err := json.Unmarshal(result.Body.Bytes(), &response); err != nil || response["accepted"] != true ||
		response["test"] != true || response["dispatched"] != false || response["run_id"] != nil {
		t.Fatalf("test response = %v, %v", response, err)
	}
}

func TestFlareV1RejectsInvalidEnvelopeBeforeJournalClaim(t *testing.T) {
	r, dispatched, j, token := newTestReceiverForProvider(t, "test-secret", ProviderFlareV1)
	configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1"}`)
	router := chi.NewRouter()
	r.Mount(router)
	now := r.now()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	valid := []byte(flareV1TestBody)
	tests := []struct {
		name   string
		body   []byte
		mutate func(*http.Request)
		status int
	}{
		{"missing timestamp", valid, func(req *http.Request) { req.Header.Del("X-Flare-Automation-Timestamp") }, http.StatusUnauthorized},
		{"repeated timestamp", valid, func(req *http.Request) { req.Header.Add("X-Flare-Automation-Timestamp", timestamp) }, http.StatusUnauthorized},
		{"stale timestamp", valid, func(req *http.Request) {
			req.Header.Set("X-Flare-Automation-Timestamp", strconv.FormatInt(now.Add(-flareV1Skew-time.Second).Unix(), 10))
		}, http.StatusUnauthorized},
		{"future timestamp", valid, func(req *http.Request) {
			req.Header.Set("X-Flare-Automation-Timestamp", strconv.FormatInt(now.Add(flareV1Skew+time.Second).Unix(), 10))
		}, http.StatusUnauthorized},
		{"leading-zero timestamp", valid, func(req *http.Request) { req.Header.Set("X-Flare-Automation-Timestamp", "0"+timestamp) }, http.StatusUnauthorized},
		{"wrong signature", valid, func(req *http.Request) {
			req.Header.Set("X-Flare-Automation-Signature", "sha256="+strings.Repeat("0", 64))
		}, http.StatusUnauthorized},
		{"repeated signature", valid, func(req *http.Request) {
			req.Header.Add("X-Flare-Automation-Signature", "sha256="+strings.Repeat("0", 64))
		}, http.StatusUnauthorized},
		{"uppercase signature", valid, func(req *http.Request) {
			req.Header.Set("X-Flare-Automation-Signature", strings.ToUpper(req.Header.Get("X-Flare-Automation-Signature")))
		}, http.StatusUnauthorized},
		{"unsigned event header changed", valid, func(req *http.Request) { req.Header.Set("X-Flare-Automation-Event", "rollback") }, http.StatusBadRequest},
		{"repeated event header", valid, func(req *http.Request) { req.Header.Add("X-Flare-Automation-Event", "new_issue") }, http.StatusBadRequest},
		{"wrong project", []byte(strings.Replace(flareV1TestBody, `"project_id":"project-1"`, `"project_id":"project-2"`, 1)), nil, http.StatusBadRequest},
		{"unknown telemetry field", []byte(strings.Replace(flareV1TestBody, `"schema":`, `"stack":"secret","schema":`, 1)), nil, http.StatusBadRequest},
		{"duplicate schema", []byte(strings.Replace(flareV1TestBody, `"schema":`, `"schema":"flare.automation.v1","schema":`, 1)), nil, http.StatusBadRequest},
		{"escaped duplicate schema", []byte(strings.Replace(flareV1TestBody, `"schema":`, `"\u0073chema":"flare.automation.v1","schema":`, 1)), nil, http.StatusBadRequest},
		{"unsupported schema", []byte(strings.Replace(flareV1TestBody, `"flare.automation.v1"`, `"flare.automation.v2"`, 1)), nil, http.StatusBadRequest},
		{"unknown event", []byte(strings.Replace(flareV1TestBody, `"event":"new_issue"`, `"event":"execute"`, 1)), nil, http.StatusBadRequest},
		{"negative count", []byte(strings.Replace(flareV1TestBody, `"event_count":3`, `"event_count":-1`, 1)), nil, http.StatusBadRequest},
		{"null count", []byte(strings.Replace(flareV1TestBody, `"event_count":3`, `"event_count":null`, 1)), nil, http.StatusBadRequest},
		{"noncanonical observed time", []byte(strings.Replace(flareV1TestBody, `"2023-11-14T22:13:20Z"`, `"2023-11-14T23:13:20+01:00"`, 1)), nil, http.StatusBadRequest},
		{"trailing JSON", append(append([]byte(nil), valid...), []byte(`{}`)...), nil, http.StatusBadRequest},
		{"missing content type", valid, func(req *http.Request) { req.Header.Del("Content-Type") }, http.StatusUnsupportedMediaType},
		{"oversized fixed notice", append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), maxFlareV1BodyBytes)...), nil, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := flareV1Request(token, timestamp, "new_issue", tc.body)
			if tc.mutate != nil {
				tc.mutate(req)
			}
			result := httptest.NewRecorder()
			router.ServeHTTP(result, req)
			if result.Code != tc.status {
				body, _ := io.ReadAll(result.Result().Body)
				t.Fatalf("status = %d, want %d: %s", result.Code, tc.status, body)
			}
		})
	}
	if dispatched.calls.Load() != 0 {
		t.Fatalf("invalid notices dispatched %d workflows", dispatched.calls.Load())
	}
	// A rejected signed body must not reserve the delivery identity. A fixed
	// follow-up notice remains claimable and receives a durable run receipt.
	accepted := httptest.NewRecorder()
	router.ServeHTTP(accepted, flareV1Request(token, timestamp, "new_issue", valid))
	if accepted.Code != http.StatusAccepted || dispatched.calls.Load() != 1 {
		t.Fatalf("valid follow-up = status %d, dispatches %d", accepted.Code, dispatched.calls.Load())
	}
}

func TestFlareV1MissingProjectBindingFailsClosed(t *testing.T) {
	r, dispatched, _, token := newTestReceiverForProvider(t, "test-secret", ProviderFlareV1)
	router := chi.NewRouter()
	r.Mount(router)
	result := httptest.NewRecorder()
	router.ServeHTTP(result, flareV1Request(token, strconv.FormatInt(r.now().Unix(), 10), "new_issue", []byte(flareV1TestBody)))
	if result.Code != http.StatusBadRequest || dispatched.calls.Load() != 0 {
		t.Fatalf("unbound trigger = status %d, dispatches %d", result.Code, dispatched.calls.Load())
	}
}

func TestFlareV1WrongProviderAndAlternateRouteRefuseBeforeSecretRead(t *testing.T) {
	for _, provider := range []string{"generic", ProviderAutomationV1, ProviderHashV1, ProviderFlareV1} {
		t.Run(provider, func(t *testing.T) {
			r, d, j, token := newTestReceiverForProvider(t, "test-secret", provider)
			configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1"}`)
			var reads atomic.Int32
			r.Vault = flareVaultFunc(func(context.Context, string) (*vault.Secret, error) {
				reads.Add(1)
				return vault.NewSecret([]byte("test-secret")), nil
			})
			router := chi.NewRouter()
			r.Mount(router)
			req := flareV1Request(token, strconv.FormatInt(r.now().Unix(), 10), "new_issue", []byte(flareV1TestBody))
			if provider == ProviderFlareV1 {
				req.URL.Path = "/webhook/" + token
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != 404 || reads.Load() != 0 || d.calls.Load() != 0 {
				t.Fatalf("refusal=%d reads=%d dispatches=%d", w.Code, reads.Load(), d.calls.Load())
			}
		})
	}
}

func TestFlareV1RebindDuringAuthenticationReleasesClaim(t *testing.T) {
	r, d, j, token := newTestReceiverForProvider(t, "test-secret", ProviderFlareV1)
	trig := configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1"}`)
	originalVault := r.Vault
	var once sync.Once
	r.Vault = flareVaultFunc(func(ctx context.Context, key string) (*vault.Secret, error) {
		once.Do(func() {
			if err := j.UpdateTriggerConfig(ctx, trig.ID, []byte(`{"flare_project_id":"project-2"}`)); err != nil {
				t.Error(err)
			}
		})
		return originalVault.Get(ctx, key)
	})
	router := chi.NewRouter()
	r.Mount(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(r.now().Unix(), 10), "new_issue", []byte(flareV1TestBody)))
	if w.Code != 503 || d.calls.Load() != 0 {
		t.Fatalf("rebound request=%d dispatches=%d", w.Code, d.calls.Load())
	}
	// Restoring the original binding must permit the same signed body. A stale
	// request must not leave a completed or still-owned delivery behind.
	if err := j.UpdateTriggerConfig(context.Background(), trig.ID, []byte(`{"flare_project_id":"project-1"}`)); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(r.now().Unix(), 10), "new_issue", []byte(flareV1TestBody)))
	if w.Code != 202 || d.calls.Load() != 1 {
		t.Fatalf("restored binding=%d dispatches=%d: %s", w.Code, d.calls.Load(), w.Body.String())
	}
}

func TestFlareV1ConcurrentDurableRunAndJournalRestart(t *testing.T) {
	ctx := context.Background()
	r, _, j, token, db, path := newTestReceiverForProviderWithDB(t, "test-secret", ProviderFlareV1)
	db.SetMaxOpenConns(1)
	configureFlareV1Trigger(t, j, token, `{"flare_project_id":"project-1","sync":true}`)
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	script := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("demo", script)
	if err != nil {
		t.Fatal(err)
	}
	version, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_1", "0.1.0", "fixture", artifact.Digest, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SetWorkflowEnabled(ctx, "wf_1", true); err != nil {
		t.Fatal(err)
	}
	makeDispatcher := func(j *journal.Journal) *dispatcher.Dispatcher {
		return &dispatcher.Dispatcher{Journal: j, Resolver: &dispatcher.SQLResolver{Journal: j}, ArtifactPath: reg.ArtifactPath, Enqueue: true, Log: r.Log}
	}
	r.Disp = makeDispatcher(j)
	router := chi.NewRouter()
	r.Mount(router)
	const senders = 6
	results := make([]*httptest.ResponseRecorder, senders)
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			router.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(r.now().Unix(), 10), "new_issue", []byte(flareV1TestBody)))
			results[i] = w
		}(i)
	}
	wg.Wait()
	var runID string
	for _, w := range results {
		if w.Code != 200 && w.Code != 202 && w.Code != 503 {
			t.Fatalf("concurrent send=%d %s", w.Code, w.Body.String())
		}
		if w.Code == 200 || w.Code == 202 {
			var receipt deliveryReceipt
			if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
				t.Fatal(err)
			}
			if runID != "" && runID != receipt.RunID {
				t.Fatal("replay returned different run")
			}
			runID = receipt.RunID
		}
	}
	if runID == "" {
		t.Fatal("no delivery committed")
	}
	run, err := j.GetRun(ctx, runID)
	if err != nil || run.Status != "queued" || run.WorkflowVersion != version || run.WorkflowArtifactSHA256 != artifact.Digest {
		t.Fatalf("durable queued run=%+v %v", run, err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM runs WHERE workflow_id='wf_1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("runs=%d %v", count, err)
	}
	// Stop and reopen the actual SQLite journal, then re-sign the unchanged
	// notice. Dedup must survive receiver and database handle replacement.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	j2 := journal.New(reopened, journal.EngineSQLite)
	restarted := &Receiver{Journal: j2, Vault: r.Vault, Disp: makeDispatcher(j2), Log: r.Log, Now: func() time.Time { return r.now().Add(time.Minute) }}
	router2 := chi.NewRouter()
	restarted.Mount(router2)
	w := httptest.NewRecorder()
	router2.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(restarted.now().Unix(), 10), "new_issue", []byte(flareV1TestBody)))
	var receipt deliveryReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || w.Code != 200 || !receipt.Deduped || receipt.RunID != runID {
		t.Fatalf("restart replay=%d %+v %v", w.Code, receipt, err)
	}
	// Inject the actual two-write crash window: the dispatcher commits a run,
	// then the delivery-completion update fails. After a journal restart and
	// lease expiry, the authenticated body must resolve that same durable run.
	if _, err := reopened.ExecContext(ctx, `CREATE TRIGGER fail_flare_completion BEFORE UPDATE ON webhook_deliveries
		WHEN NEW.completed_at IS NOT NULL BEGIN SELECT RAISE(FAIL,'synthetic receipt failure'); END`); err != nil {
		t.Fatal(err)
	}
	crashBody := []byte(strings.Replace(flareV1TestBody, `"issue-1"`, `"issue-crash"`, 1))
	w = httptest.NewRecorder()
	router2.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(restarted.now().Unix(), 10), "new_issue", crashBody))
	if w.Code != 500 {
		t.Fatalf("injected completion failure=%d %s", w.Code, w.Body.String())
	}
	var crashRunID string
	if err := reopened.QueryRowContext(ctx, `SELECT id FROM runs WHERE workflow_id='wf_1' AND id<>?`, runID).Scan(&crashRunID); err != nil {
		t.Fatalf("run did not commit before completion failure: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.ExecContext(ctx, `DROP TRIGGER fail_flare_completion`); err != nil {
		t.Fatal(err)
	}
	j2 = journal.New(reopened, journal.EngineSQLite)
	restarted = &Receiver{Journal: j2, Vault: r.Vault, Disp: makeDispatcher(j2), Log: r.Log, Now: func() time.Time { return r.now().Add(7 * time.Minute) }}
	router2 = chi.NewRouter()
	restarted.Mount(router2)
	w = httptest.NewRecorder()
	router2.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(restarted.now().Unix(), 10), "new_issue", crashBody))
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || w.Code != 202 || receipt.RunID != crashRunID {
		t.Fatalf("crash recovery=%d %+v %v", w.Code, receipt, err)
	}
	if err := reopened.QueryRowContext(ctx, `SELECT count(*) FROM runs WHERE workflow_id='wf_1'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("recovery duplicated a durable run=%d %v", count, err)
	}
	// A new body still passes the current workflow kill switch, even when a
	// legacy trigger requested synchronous execution.
	if err := j2.SetWorkflowEnabled(ctx, "wf_1", false); err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Replace(flareV1TestBody, `"issue-1"`, `"issue-2"`, 1))
	w = httptest.NewRecorder()
	router2.ServeHTTP(w, flareV1Request(token, strconv.FormatInt(restarted.now().Unix(), 10), "new_issue", body))
	if w.Code != 503 {
		t.Fatalf("disabled workflow=%d %s", w.Code, w.Body.String())
	}
	if err := reopened.QueryRowContext(ctx, `SELECT count(*) FROM runs WHERE workflow_id='wf_1'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("disabled dispatch created run=%d %v", count, err)
	}
}

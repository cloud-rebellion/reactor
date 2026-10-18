package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/runtime/webhookpolicy"
	"github.com/bright-interaction/reactor/internal/vault"
	"github.com/go-chi/chi/v5"
)

func genericPolicyRequest(token string) *http.Request {
	body := []byte(`{"stack":"private telemetry must not reach a Flare run","event":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook/"+token, strings.NewReader(string(body)))
	req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("test-secret"), body))
	return req
}

func TestWebhookStoredProviderPolicyRefusesBeforeSecretClaimOrRun(t *testing.T) {
	for _, tc := range []struct{ name, dag string }{
		{"generic trigger predates Flare publication", `{"triggers":[{"kind":"webhook","provider":"flare-v1"}]}`},
		{"conflicting providers", `{"triggers":[{"kind":"webhook","provider":"generic"},{"kind":"webhook","provider":"flare-v1"}]}`},
		{"malformed", `{"triggers":`},
		{"null triggers", `{"triggers":null}`},
		{"duplicate policy key", `{"triggers":[{"kind":"webhook","provider":"flare-v1"}],"triggers":[]}`},
		{"duplicate verifier", `{"triggers":[{"kind":"webhook","provider":"flare-v1","provider":"generic"}]}`},
		{"case alias", `{"triggers":[{"kind":"webhook","provider":"flare-v1","Provider":"generic"}]}`},
		{"oversized", `{"padding":"` + strings.Repeat("x", webhookpolicy.MaxDAGBytes) + `","triggers":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, dispatched, j, token, db, _ := newTestReceiverForProviderWithDB(t, "test-secret", "generic")
			// The generic trigger is already active before the stricter (or
			// unreadable legacy) workflow policy is published.
			if _, err := j.RecordWorkflowVersion(context.Background(), "wf_1", "1", "new-source", json.RawMessage(tc.dag)); err != nil {
				t.Fatal(err)
			}
			var reads atomic.Int32
			r.Vault = flareVaultFunc(func(context.Context, string) (*vault.Secret, error) {
				reads.Add(1)
				return vault.NewSecret([]byte("test-secret")), nil
			})
			router := chi.NewRouter()
			r.Mount(router)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, genericPolicyRequest(token))
			if w.Code != http.StatusServiceUnavailable || reads.Load() != 0 || dispatched.calls.Load() != 0 {
				t.Fatalf("stale provider policy accepted: status=%d reads=%d dispatches=%d", w.Code, reads.Load(), dispatched.calls.Load())
			}
			for _, table := range []string{"webhook_deliveries", "runs"} {
				var count int
				if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatalf("policy refusal changed %s: %d, %v", table, count, err)
				}
			}
		})
	}
}

func TestWebhookProviderPublicationRaceFailsAtExactDispatchVersion(t *testing.T) {
	ctx := context.Background()
	r, _, j, token, db, _ := newTestReceiverForProviderWithDB(t, "test-secret", "generic")
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_1", "1", "generic-source", digest, json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"generic"}]}`)); err != nil {
		t.Fatal(err)
	}
	var reads, artifactReads atomic.Int32
	r.Vault = flareVaultFunc(func(context.Context, string) (*vault.Secret, error) {
		reads.Add(1)
		// Publication happens after the receiver's stored-DAG check, while
		// authenticating the still-generic trigger, before dispatch selects v3.
		if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_1", "1", "flare-source", digest, json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"flare-v1"}]}`)); err != nil {
			return nil, err
		}
		return vault.NewSecret([]byte("test-secret")), nil
	})
	r.Disp = &dispatcher.Dispatcher{Journal: j, Resolver: &dispatcher.SQLResolver{Journal: j}, Enqueue: true, Log: r.Log,
		ArtifactPath: func(string, string) (string, error) { artifactReads.Add(1); return "/must-not-execute", nil }}
	router := chi.NewRouter()
	r.Mount(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, genericPolicyRequest(token))
	if w.Code != http.StatusInternalServerError || reads.Load() != 1 || artifactReads.Load() != 0 {
		t.Fatalf("publication race escaped exact-version policy: status=%d secrets=%d artifact=%d", w.Code, reads.Load(), artifactReads.Load())
	}
	for _, table := range []string{"webhook_deliveries", "runs"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("publication race changed %s: %d, %v", table, count, err)
		}
	}
}

func TestWebhookRuntimePolicyPreservesMatchingGenericProvider(t *testing.T) {
	r, dispatched, j, token := newTestReceiverForProvider(t, "test-secret", "generic")
	if _, err := j.RecordWorkflowVersion(context.Background(), "wf_1", "1", "source", json.RawMessage(`{"triggers":[{"kind":"webhook","provider":"generic"}]}`)); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	r.Mount(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, genericPolicyRequest(token))
	if w.Code != http.StatusAccepted || dispatched.calls.Load() != 1 {
		t.Fatalf("matching generic provider broke: %d dispatches=%d", w.Code, dispatched.calls.Load())
	}
}

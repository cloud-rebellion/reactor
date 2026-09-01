package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/vault"
	_ "modernc.org/sqlite"
)

// captureDispatcher records every Dispatch call so tests can assert on
// payload + trigger identity.
type captureDispatcher struct {
	calls      atomic.Int32
	asyncCalls atomic.Int32
	syncCalls  atomic.Int32
	last       []byte
	trig       journal.Trigger
	err        error
}

func (c *captureDispatcher) DispatchWebhook(_ context.Context, t journal.Trigger, payload []byte) (string, error) {
	c.calls.Add(1)
	c.asyncCalls.Add(1)
	c.last = append([]byte(nil), payload...)
	c.trig = t
	if c.err != nil {
		return "", c.err
	}
	return "run_async", nil
}

func (c *captureDispatcher) DispatchSync(_ context.Context, t journal.Trigger, payload []byte, _ time.Duration) (string, string, json.RawMessage, error) {
	c.calls.Add(1)
	c.syncCalls.Add(1)
	c.last = append([]byte(nil), payload...)
	c.trig = t
	return "run_sync", "succeeded", json.RawMessage(`{"ok":true}`), nil
}

func newTestReceiver(t *testing.T, secretValue string) (*Receiver, *captureDispatcher, *journal.Journal, string) {
	return newTestReceiverForProvider(t, secretValue, "generic")
}

func newTestReceiverForProvider(t *testing.T, secretValue, provider string) (*Receiver, *captureDispatcher, *journal.Journal, string) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "wh.db")
	url := "sqlite://" + dbPath

	silent := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	if err := migrate.Up(context.Background(), silent, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	j := journal.New(db, journal.EngineSQLite)

	if err := j.CreateWorkflow(context.Background(), "wf_1", "demo", "h", "0.1.0", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("workflow: %v", err)
	}

	v, err := vault.NewStore(vault.NewMemoryBackend(), bytesN(32, 0xAB))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	if err := v.Put(context.Background(), "cred_hmac", []byte(secretValue)); err != nil {
		t.Fatalf("vault put: %v", err)
	}

	tokenID, _ := journal.NewTokenID()
	if _, err := j.CreateWebhookTrigger(context.Background(), "wf_1", tokenID, "cred_hmac", provider, []byte(`{}`)); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	disp := &captureDispatcher{}
	r := &Receiver{
		Journal: j,
		Vault:   v,
		Disp:    disp,
		Log:     silent,
		Now:     func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return r, disp, j, tokenID
}

func bytesN(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func signAutomation(secret []byte, timestamp, deliveryID string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write([]byte(deliveryID))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func signHash(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func hashLifecycleBody(eventID, kind string) []byte {
	return []byte(fmt.Sprintf(`{
		"event_id":%q,
		"kind":%q,
		"occurred_at":"2026-09-01T10:30:00Z",
		"org_id":"org_hash",
		"automation_request_id":"request_hash",
		"document":{"id":"document_hash"},
		"recipient":{"id":"recipient_hash"},
		"payload":{"customer_email":"private@example.test"}
	}`, eventID, kind))
}

func TestWebhookAutomationV1HappyPath(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiverForProvider(t, "test-secret", ProviderAutomationV1)
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	timestamp := strconv.FormatInt(r.now().Unix(), 10)
	deliveryID := "evt_123"
	body := []byte(`{"event_id":"evt_123","nested":{"event_id":"not-top-level"}}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Timestamp", timestamp)
	req.Header.Set("X-Webhook-Delivery", deliveryID)
	req.Header.Set("X-Webhook-Signature", "sha256="+signAutomation([]byte("test-secret"), timestamp, deliveryID, body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d %s, want 202", resp.StatusCode, buf)
	}
	var receipt deliveryReceipt
	if err := json.NewDecoder(resp.Body).Decode(&receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Accepted || receipt.Deduped || receipt.RunID != "run_async" {
		t.Fatalf("receipt = %+v", receipt)
	}
	if disp.calls.Load() != 1 || string(disp.last) != string(body) {
		t.Fatalf("dispatch count/body = %d/%q", disp.calls.Load(), disp.last)
	}
}

func TestWebhookAutomationV1RequiresStrictJSONContentType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		contentTypes []string
		wantStatus   int
	}{
		{name: "missing", wantStatus: http.StatusUnsupportedMediaType},
		{name: "repeated", contentTypes: []string{"application/json", "application/json"}, wantStatus: http.StatusUnsupportedMediaType},
		{name: "non json", contentTypes: []string{"text/plain"}, wantStatus: http.StatusUnsupportedMediaType},
		{name: "structured suffix", contentTypes: []string{"application/problem+json"}, wantStatus: http.StatusUnsupportedMediaType},
		{name: "non utf8", contentTypes: []string{"application/json; charset=iso-8859-1"}, wantStatus: http.StatusUnsupportedMediaType},
		{name: "extra parameter", contentTypes: []string{"application/json; charset=utf-8; profile=bridge"}, wantStatus: http.StatusUnsupportedMediaType},
		{name: "plain json", contentTypes: []string{"application/json"}, wantStatus: http.StatusAccepted},
		{name: "explicit utf8", contentTypes: []string{"application/json; charset=UTF-8"}, wantStatus: http.StatusAccepted},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, disp, _, tokenID := newTestReceiverForProvider(t, "test-secret", ProviderAutomationV1)
			router := chi.NewRouter()
			r.Mount(router)
			timestamp := strconv.FormatInt(r.now().Unix(), 10)
			deliveryID := "evt_content_type"
			body := []byte(`{"event_id":"evt_content_type"}`)
			req := httptest.NewRequest(http.MethodPost, "/webhook/"+tokenID, bytes.NewReader(body))
			if tc.contentTypes != nil {
				req.Header[http.CanonicalHeaderKey("Content-Type")] = tc.contentTypes
			}
			req.Header.Set("X-Webhook-Timestamp", timestamp)
			req.Header.Set("X-Webhook-Delivery", deliveryID)
			req.Header.Set("X-Webhook-Signature", "sha256="+
				signAutomation([]byte("test-secret"), timestamp, deliveryID, body))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("got %d %s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			wantDispatches := int32(0)
			if tc.wantStatus == http.StatusAccepted {
				wantDispatches = 1
			}
			if disp.calls.Load() != wantDispatches {
				t.Fatalf("dispatch count = %d, want %d", disp.calls.Load(), wantDispatches)
			}
		})
	}
}

func TestWebhookGenericPreservesContentTypeAndSignatureCompatibility(t *testing.T) {
	t.Parallel()
	r, disp, _, tokenID := newTestReceiverForProvider(t, "test-secret", "generic")
	router := chi.NewRouter()
	r.Mount(router)
	body := []byte("not-json")
	req := httptest.NewRequest(http.MethodPost, "/webhook/"+tokenID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Webhook-Delivery", "evt_generic_compatibility")
	req.Header.Set("X-Webhook-Signature", "sha256="+strings.ToUpper(sign([]byte("test-secret"), body)))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("generic compatibility request got %d %s, want 202", recorder.Code, recorder.Body.String())
	}
	if disp.calls.Load() != 1 || string(disp.last) != string(body) {
		t.Fatalf("generic dispatch count/body = %d/%q", disp.calls.Load(), disp.last)
	}
}

func TestWebhookAutomationV1RejectsInvalidEnvelopesBeforeDispatch(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiverForProvider(t, "test-secret", ProviderAutomationV1)
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	now := r.now()
	validTimestamp := strconv.FormatInt(now.Unix(), 10)
	type testCase struct {
		name             string
		body             []byte
		timestamp        string
		deliveryID       string
		signedTimestamp  string
		signedDeliveryID string
		omitTimestamp    bool
		omitDeliveryID   bool
		wantStatus       int
	}
	tests := []testCase{
		{
			name: "missing timestamp", body: []byte(`{"event_id":"evt_missing_ts"}`),
			timestamp: validTimestamp, deliveryID: "evt_missing_ts", omitTimestamp: true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "malformed timestamp", body: []byte(`{"event_id":"evt_bad_ts"}`),
			timestamp: "not-unix-seconds", deliveryID: "evt_bad_ts",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "stale timestamp", body: []byte(`{"event_id":"evt_stale"}`),
			timestamp: strconv.FormatInt(now.Add(-automationSkew-time.Second).Unix(), 10), deliveryID: "evt_stale",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "future timestamp", body: []byte(`{"event_id":"evt_future"}`),
			timestamp: strconv.FormatInt(now.Add(automationSkew+time.Second).Unix(), 10), deliveryID: "evt_future",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "missing delivery", body: []byte(`{"event_id":"evt_missing_delivery"}`),
			timestamp: validTimestamp, deliveryID: "evt_missing_delivery", omitDeliveryID: true,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "tampered delivery header", body: []byte(`{"event_id":"evt_tampered"}`),
			timestamp: validTimestamp, deliveryID: "evt_tampered", signedDeliveryID: "evt_original",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "body and delivery mismatch", body: []byte(`{"event_id":"evt_body"}`),
			timestamp: validTimestamp, deliveryID: "evt_header",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "duplicate event id", body: []byte(`{"event_id":"evt_duplicate","event_id":"evt_duplicate"}`),
			timestamp: validTimestamp, deliveryID: "evt_duplicate",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "escaped duplicate event id", body: []byte(`{"event_id":"evt_escaped","\u0065vent_id":"evt_escaped"}`),
			timestamp: validTimestamp, deliveryID: "evt_escaped",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing event id", body: []byte(`{"customer":{}}`),
			timestamp: validTimestamp, deliveryID: "evt_missing",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "non-string event id", body: []byte(`{"event_id":123}`),
			timestamp: validTimestamp, deliveryID: "123",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "top-level array", body: []byte(`["evt_array"]`),
			timestamp: validTimestamp, deliveryID: "evt_array",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "trailing JSON", body: []byte(`{"event_id":"evt_trailing"}{}`),
			timestamp: validTimestamp, deliveryID: "evt_trailing",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signedTimestamp := tc.signedTimestamp
			if signedTimestamp == "" {
				signedTimestamp = tc.timestamp
			}
			signedDeliveryID := tc.signedDeliveryID
			if signedDeliveryID == "" {
				signedDeliveryID = tc.deliveryID
			}
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if !tc.omitTimestamp {
				req.Header.Set("X-Webhook-Timestamp", tc.timestamp)
			}
			if !tc.omitDeliveryID {
				req.Header.Set("X-Webhook-Delivery", tc.deliveryID)
			}
			req.Header.Set("X-Webhook-Signature", "sha256="+
				signAutomation([]byte("test-secret"), signedTimestamp, signedDeliveryID, tc.body))

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				buf, _ := io.ReadAll(resp.Body)
				t.Fatalf("got %d %s, want %d", resp.StatusCode, buf, tc.wantStatus)
			}
		})
	}
	if disp.calls.Load() != 0 {
		t.Fatalf("invalid envelopes dispatched %d runs", disp.calls.Load())
	}

	// The signed-but-mismatched evt_header request above must be rejected
	// before it creates a delivery claim. A corrected request with that same
	// delivery ID must therefore be accepted, not conflict with stale input.
	correctedBody := []byte(`{"event_id":"evt_header"}`)
	corrected, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(correctedBody))
	corrected.Header.Set("Content-Type", "application/json")
	corrected.Header.Set("X-Webhook-Timestamp", validTimestamp)
	corrected.Header.Set("X-Webhook-Delivery", "evt_header")
	corrected.Header.Set("X-Webhook-Signature", "sha256="+
		signAutomation([]byte("test-secret"), validTimestamp, "evt_header", correctedBody))
	resp, err := http.DefaultClient.Do(corrected)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		responseBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("corrected envelope got %d %s, want 202", resp.StatusCode, responseBody)
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("corrected envelope dispatch count = %d, want 1", disp.calls.Load())
	}
}

func TestVerifyAutomationV1FixedVector(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event_id":"evt_123"}`)
	header := make(http.Header)
	header.Set("X-Webhook-Timestamp", "1700000000")
	header.Set("X-Webhook-Delivery", "evt_123")
	header.Set("X-Webhook-Signature", "sha256=b3a6d73ffec1e2bd10e702f4357d7d7f7069dea9c783c3e03be63b0b92fab3a9")
	if err := verifyAutomationV1(header, body, []byte("test-secret"), time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("fixed vector rejected: %v", err)
	}
}

func TestVerifyAutomationV1RejectsNonCanonicalHeaders(t *testing.T) {
	t.Parallel()
	const (
		secret    = "test-secret"
		timestamp = "1700000000"
	)
	body := []byte(`{"event_id":"evt_123"}`)
	tests := []struct {
		name       string
		timestamp  string
		deliveryID string
	}{
		{name: "timestamp whitespace", timestamp: " 1700000000", deliveryID: "evt_123"},
		{name: "timestamp plus prefix", timestamp: "+1700000000", deliveryID: "evt_123"},
		{name: "delivery whitespace", timestamp: timestamp, deliveryID: " evt_123"},
		{name: "delivery control", timestamp: timestamp, deliveryID: "evt_123\n"},
		{name: "delivery too long", timestamp: timestamp, deliveryID: strings.Repeat("e", 201)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			header["X-Webhook-Timestamp"] = []string{tc.timestamp}
			header["X-Webhook-Delivery"] = []string{tc.deliveryID}
			header.Set("X-Webhook-Signature", "sha256="+
				signAutomation([]byte(secret), tc.timestamp, tc.deliveryID, body))
			if err := verifyAutomationV1(header, body, []byte(secret), time.Unix(1_700_000_000, 0)); err == nil {
				t.Fatal("non-canonical envelope accepted")
			}
		})
	}

	header := make(http.Header)
	header["X-Webhook-Timestamp"] = []string{timestamp}
	header["X-Webhook-Delivery"] = []string{"evt_123", "evt_123"}
	header.Set("X-Webhook-Signature", "sha256="+
		signAutomation([]byte(secret), timestamp, "evt_123", body))
	if err := verifyAutomationV1(header, body, []byte(secret), time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("repeated delivery header accepted")
	}

	validSignature := signAutomation([]byte(secret), timestamp, "evt_123", body)
	for _, tc := range []struct {
		name      string
		signature []string
	}{
		{name: "uppercase digest", signature: []string{"sha256=" + strings.ToUpper(validSignature)}},
		{name: "short digest", signature: []string{"sha256=" + strings.Repeat("a", 62)}},
		{name: "long digest", signature: []string{"sha256=" + strings.Repeat("a", 66)}},
		{name: "non hex digest", signature: []string{"sha256=" + strings.Repeat("g", 64)}},
		{name: "repeated signature header", signature: []string{"sha256=" + validSignature, "sha256=" + validSignature}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("X-Webhook-Timestamp", timestamp)
			header.Set("X-Webhook-Delivery", "evt_123")
			header[http.CanonicalHeaderKey("X-Webhook-Signature")] = tc.signature
			if err := verifyAutomationV1(header, body, []byte(secret), time.Unix(1_700_000_000, 0)); err == nil {
				t.Fatal("non-canonical signature accepted")
			}
		})
	}
}

func TestVerifyHashV1FixedVector(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event_id":"evt_hash","data":{"x":1}}`)
	header := make(http.Header)
	header.Set("X-Hash-Signature", "t=1700000000,v1=959d873de800f9bb3c9b886f9172054d834cd21d7b61bb513b5bfcf97c1f43e3")
	if err := verifyHashV1(header, body, []byte("hash-secret"), time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("fixed vector rejected: %v", err)
	}
}

func TestVerifyHashV1RejectsNonCanonicalOrInvalidEnvelopes(t *testing.T) {
	t.Parallel()
	const timestamp = "1700000000"
	secret := []byte("hash-secret")
	body := []byte(`{"event_id":"evt_hash"}`)
	now := time.Unix(1_700_000_000, 0)
	validSignature := signHash(secret, timestamp, body)

	tests := []struct {
		name   string
		header []string
		body   []byte
		now    time.Time
	}{
		{name: "missing header", body: body, now: now},
		{name: "repeated header", header: []string{
			"t=" + timestamp + ",v1=" + validSignature,
			"t=" + timestamp + ",v1=" + validSignature,
		}, body: body, now: now},
		{name: "space after comma", header: []string{"t=" + timestamp + ", v1=" + validSignature}, body: body, now: now},
		{name: "reversed fields", header: []string{"v1=" + validSignature + ",t=" + timestamp}, body: body, now: now},
		{name: "extra field", header: []string{"t=" + timestamp + ",v1=" + validSignature + ",v0=" + validSignature}, body: body, now: now},
		{name: "timestamp whitespace", header: []string{"t= " + timestamp + ",v1=" + validSignature}, body: body, now: now},
		{name: "timestamp plus prefix", header: []string{"t=+" + timestamp + ",v1=" + validSignature}, body: body, now: now},
		{name: "timestamp leading zero", header: []string{"t=0" + timestamp + ",v1=" + signHash(secret, "0"+timestamp, body)}, body: body, now: now},
		{name: "uppercase digest", header: []string{"t=" + timestamp + ",v1=" + strings.ToUpper(validSignature)}, body: body, now: now},
		{name: "short digest", header: []string{"t=" + timestamp + ",v1=00"}, body: body, now: now},
		{name: "wrong digest", header: []string{"t=" + timestamp + ",v1=" + strings.Repeat("0", sha256.Size*2)}, body: body, now: now},
		{name: "tampered raw body", header: []string{"t=" + timestamp + ",v1=" + validSignature}, body: []byte(" " + string(body)), now: now},
		{name: "stale timestamp", header: []string{"t=" + timestamp + ",v1=" + validSignature}, body: body, now: now.Add(hashSkew + time.Second)},
		{name: "future timestamp", header: []string{"t=" + timestamp + ",v1=" + validSignature}, body: body, now: now.Add(-hashSkew - time.Second)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			if tc.header != nil {
				header[http.CanonicalHeaderKey("X-Hash-Signature")] = tc.header
			}
			if err := verifyHashV1(header, tc.body, secret, tc.now); err == nil {
				t.Fatal("invalid hash-v1 envelope accepted")
			}
		})
	}
}

func TestHashEventIDRequiresOneTopLevelNonEmptyString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{name: "valid", body: `{"event_id":"evt_hash","nested":{"event_id":"nested"}}`, want: "evt_hash"},
		{name: "valid with trailing whitespace", body: "{\"event_id\":\"evt_space\"}\n\t", want: "evt_space"},
		{name: "missing", body: `{"type":"document.sent"}`, wantErr: true},
		{name: "empty", body: `{"event_id":""}`, wantErr: true},
		{name: "surrounding whitespace", body: `{"event_id":" evt_hash "}`, wantErr: true},
		{name: "control character", body: `{"event_id":"evt_hash\n"}`, wantErr: true},
		{name: "too long", body: `{"event_id":"` + strings.Repeat("e", 201) + `"}`, wantErr: true},
		{name: "null", body: `{"event_id":null}`, wantErr: true},
		{name: "non string", body: `{"event_id":123}`, wantErr: true},
		{name: "duplicate", body: `{"event_id":"first","event_id":"second"}`, wantErr: true},
		{name: "escaped duplicate", body: `{"event_id":"first","\u0065vent_id":"second"}`, wantErr: true},
		{name: "array", body: `["evt_hash"]`, wantErr: true},
		{name: "invalid utf8", body: "{\"event_id\":\"\xff\"}", wantErr: true},
		{name: "trailing object", body: `{"event_id":"evt_hash"}{}`, wantErr: true},
		{name: "malformed", body: `{"event_id":"evt_hash"`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := hashEventID([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("hashEventID(%q) = %q, want error", tc.body, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("hashEventID(%q) = %q, %v; want %q", tc.body, got, err, tc.want)
			}
		})
	}
}

func TestWebhookHashV1UsesSignedEventIDForDeduplication(t *testing.T) {
	t.Parallel()
	r, disp, _, tokenID := newTestReceiverForProvider(t, "hash-secret", ProviderHashV1)
	router := chi.NewRouter()
	r.Mount(router)
	timestamp := strconv.FormatInt(r.now().Unix(), 10)

	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/webhook/"+tokenID, bytes.NewReader(body))
		req.Header.Set("X-Hash-Signature", "t="+timestamp+",v1="+signHash([]byte("hash-secret"), timestamp, body))
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	firstBody := hashLifecycleBody("evt_hash", "document.sent")
	if first := post(firstBody); first.Code != http.StatusAccepted {
		t.Fatalf("first callback got %d %s, want 202", first.Code, first.Body.String())
	}
	if replay := post(firstBody); replay.Code != http.StatusOK {
		t.Fatalf("replay got %d %s, want 200", replay.Code, replay.Body.String())
	}
	differentBody := hashLifecycleBody("evt_hash", "document.completed")
	if conflict := post(differentBody); conflict.Code != http.StatusConflict {
		t.Fatalf("same event_id with different body got %d %s, want 409", conflict.Code, conflict.Body.String())
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("dispatch count = %d, want 1", disp.calls.Load())
	}
	if strings.Contains(string(disp.last), "recipient") || strings.Contains(string(disp.last), "payload") ||
		strings.Contains(string(disp.last), "private@example.test") {
		t.Fatalf("hash-v1 run input retained provider payload or recipient data: %s", disp.last)
	}
	for _, required := range []string{"event_id", "kind", "occurred_at", "org_id", "automation_request_id", "document"} {
		if !strings.Contains(string(disp.last), `"`+required+`"`) {
			t.Fatalf("hash-v1 run input omitted %q: %s", required, disp.last)
		}
	}
}

func TestWebhookHashV1RejectsCaseVariantEnvelopeBeforeDispatch(t *testing.T) {
	t.Parallel()
	r, disp, _, tokenID := newTestReceiverForProvider(t, "hash-secret", ProviderHashV1)
	router := chi.NewRouter()
	r.Mount(router)
	timestamp := strconv.FormatInt(r.now().Unix(), 10)
	body := bytes.Replace(hashLifecycleBody("evt_hash_case", "document.sent"), []byte(`"kind"`), []byte(`"KIND"`), 1)
	req := httptest.NewRequest(http.MethodPost, "/webhook/"+tokenID, bytes.NewReader(body))
	req.Header.Set("X-Hash-Signature", "t="+timestamp+",v1="+signHash([]byte("hash-secret"), timestamp, body))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("case-variant envelope got %d %s, want 400", recorder.Code, recorder.Body.String())
	}
	if disp.calls.Load() != 0 {
		t.Fatalf("invalid Hash envelope dispatched %d runs", disp.calls.Load())
	}
}

func TestWebhookHashV1IgnoresLegacySyncConfig(t *testing.T) {
	t.Parallel()
	r, disp, j, _ := newTestReceiverForProvider(t, "hash-secret", ProviderHashV1)
	tokenID, err := journal.NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateWebhookTrigger(context.Background(), "wf_1", tokenID, "cred_hmac", ProviderHashV1,
		[]byte(`{"sync":true,"timeout_seconds":120}`)); err != nil {
		t.Fatalf("create legacy sync trigger: %v", err)
	}
	router := chi.NewRouter()
	r.Mount(router)
	timestamp := strconv.FormatInt(r.now().Unix(), 10)
	body := hashLifecycleBody("evt_hash_async", "document.completed")
	req := httptest.NewRequest(http.MethodPost, "/webhook/"+tokenID, bytes.NewReader(body))
	req.Header.Set("X-Hash-Signature", "t="+timestamp+",v1="+signHash([]byte("hash-secret"), timestamp, body))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("legacy sync callback got %d %s, want async 202", recorder.Code, recorder.Body.String())
	}
	var receipt deliveryReceipt
	if err := json.NewDecoder(recorder.Body).Decode(&receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.RunID != "run_async" || disp.asyncCalls.Load() != 1 || disp.syncCalls.Load() != 0 {
		t.Fatalf("receipt/calls = %+v async=%d sync=%d; want async dispatcher only",
			receipt, disp.asyncCalls.Load(), disp.syncCalls.Load())
	}
}

func TestAutomationDeliveryStatusReturnsOnlyBoundSafeResult(t *testing.T) {
	t.Parallel()
	r, _, j, tokenID := newTestReceiverForProvider(t, "test-secret", ProviderAutomationV1)
	ctx := context.Background()
	trigger, err := j.FindWebhookByToken(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}
	deliveryID := "partner/123:deal-456"
	if err := j.CreateRun(ctx, "run_status", "wf_1", "webhook", json.RawMessage(`{"private":"customer data"}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := j.ClaimWebhookDelivery(ctx, trigger.ID, ProviderAutomationV1, deliveryID,
		"payload-digest", r.now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CompleteWebhookDelivery(ctx, trigger.ID, ProviderAutomationV1, deliveryID,
		claim.ClaimToken, "run_status", r.now()); err != nil {
		t.Fatal(err)
	}

	router := chi.NewRouter()
	r.Mount(router)
	statusRequest := func() *httptest.ResponseRecorder {
		timestamp := strconv.FormatInt(r.now().Unix(), 10)
		target := "/webhook/" + tokenID + "/status?delivery_id=" + url.QueryEscape(deliveryID)
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("X-Webhook-Timestamp", timestamp)
		req.Header.Set("X-Webhook-Delivery", deliveryID)
		req.Header.Set("X-Webhook-Signature", "sha256="+
			signAutomation([]byte("test-secret"), timestamp, deliveryID, nil))
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	active := statusRequest()
	if active.Code != http.StatusAccepted {
		t.Fatalf("active status got %d %s, want 202", active.Code, active.Body.String())
	}
	if active.Header().Get("Cache-Control") != "no-store, max-age=0" ||
		active.Header().Get("Pragma") != "no-cache" || active.Header().Get("Expires") != "0" {
		t.Fatalf("active cache headers = %v", active.Header())
	}
	var activeResponse deliveryStatusResponse
	if err := json.NewDecoder(active.Body).Decode(&activeResponse); err != nil {
		t.Fatal(err)
	}
	if activeResponse.RunID != "run_status" || activeResponse.Status != "running" ||
		activeResponse.Terminal || activeResponse.HashResult != nil {
		t.Fatalf("active response = %+v", activeResponse)
	}

	if _, err := j.RecordStepStart(ctx, "run_status", "unrelated-step", 1, "", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEnd(ctx, "run_status", "unrelated-step", 1,
		json.RawMessage(`{"customer_email":"must-not-leak@example.com"}`), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordStepStart(ctx, "run_status", "hash-create-and-send", 1, "", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordStepEnd(ctx, "run_status", "hash-create-and-send", 1, json.RawMessage(
		`{"automation_request_id":"req-123","document_id":"doc-456","status":"sent","replayed":false,"customer_email":"also-must-not-leak@example.com"}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := j.MarkRunFinished(ctx, "run_status", "succeeded"); err != nil {
		t.Fatal(err)
	}

	terminal := statusRequest()
	if terminal.Code != http.StatusOK {
		t.Fatalf("terminal status got %d %s, want 200", terminal.Code, terminal.Body.String())
	}
	if strings.Contains(terminal.Body.String(), "customer") || strings.Contains(terminal.Body.String(), "private") {
		t.Fatalf("terminal response leaked workflow data: %s", terminal.Body.String())
	}
	var terminalResponse deliveryStatusResponse
	if err := json.NewDecoder(terminal.Body).Decode(&terminalResponse); err != nil {
		t.Fatal(err)
	}
	if !terminalResponse.Terminal || terminalResponse.Status != "succeeded" || terminalResponse.RunID != "run_status" ||
		terminalResponse.HashResult == nil || terminalResponse.HashResult.AutomationRequestID != "req-123" ||
		terminalResponse.HashResult.DocumentID != "doc-456" || terminalResponse.HashResult.Status != "sent" ||
		terminalResponse.HashResult.Replayed {
		t.Fatalf("terminal response = %+v", terminalResponse)
	}
}

func TestAutomationDeliveryStatusDoesNotPublishIntermediateHashResultForFailedRun(t *testing.T) {
	t.Parallel()
	receiver, _, journalStore, tokenID := newTestReceiverForProvider(t, "test-secret", ProviderAutomationV1)
	ctx := context.Background()
	trigger, err := journalStore.FindWebhookByToken(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}
	const deliveryID = "evt_failed_after_hash"
	if err := journalStore.CreateRun(ctx, "run_failed_after_hash", "wf_1", "webhook", json.RawMessage(`{"event_id":"evt_failed_after_hash"}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := journalStore.ClaimWebhookDelivery(ctx, trigger.ID, ProviderAutomationV1, deliveryID,
		"payload-digest", receiver.now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := journalStore.CompleteWebhookDelivery(ctx, trigger.ID, ProviderAutomationV1, deliveryID,
		claim.ClaimToken, "run_failed_after_hash", receiver.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := journalStore.RecordStepStart(ctx, "run_failed_after_hash", "hash-create-and-send", 1, "", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := journalStore.RecordStepEnd(ctx, "run_failed_after_hash", "hash-create-and-send", 1, json.RawMessage(
		`{"automation_request_id":"req-created","document_id":"doc-created","status":"sent","replayed":false}`), ""); err != nil {
		t.Fatal(err)
	}
	if err := journalStore.MarkRunFinished(ctx, "run_failed_after_hash", "failed"); err != nil {
		t.Fatal(err)
	}

	router := chi.NewRouter()
	receiver.Mount(router)
	timestamp := strconv.FormatInt(receiver.now().Unix(), 10)
	req := httptest.NewRequest(http.MethodGet,
		"/webhook/"+tokenID+"/status?delivery_id="+url.QueryEscape(deliveryID), nil)
	req.Header.Set("X-Webhook-Timestamp", timestamp)
	req.Header.Set("X-Webhook-Delivery", deliveryID)
	req.Header.Set("X-Webhook-Signature", "sha256="+
		signAutomation([]byte("test-secret"), timestamp, deliveryID, nil))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("failed terminal status got %d %s, want 200", recorder.Code, recorder.Body.String())
	}
	var response deliveryStatusResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.Terminal || response.Status != "failed" || response.HashResult != nil {
		t.Fatalf("failed terminal response exposed an intermediate result: %+v", response)
	}
}

func TestAutomationDeliveryStatusRejectsAmbiguityAndUnboundRuns(t *testing.T) {
	t.Parallel()
	r, _, j, tokenID := newTestReceiverForProvider(t, "test-secret", ProviderAutomationV1)
	ctx := context.Background()
	trigger, err := j.FindWebhookByToken(ctx, tokenID)
	if err != nil {
		t.Fatal(err)
	}
	now := r.now()
	incompleteID := "evt_incomplete"
	if _, err := j.ClaimWebhookDelivery(ctx, trigger.ID, ProviderAutomationV1, incompleteID,
		"payload-digest", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	hashToken, err := journal.NewTokenID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.CreateWebhookTrigger(ctx, "wf_1", hashToken, "cred_hmac", ProviderHashV1, nil); err != nil {
		t.Fatal(err)
	}

	router := chi.NewRouter()
	r.Mount(router)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	request := func(token, rawQuery, signedID string, signedBody, requestBody []byte, mutate func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/webhook/"+token+"/status?"+rawQuery, bytes.NewReader(requestBody))
		req.Header.Set("X-Webhook-Timestamp", timestamp)
		req.Header.Set("X-Webhook-Delivery", signedID)
		req.Header.Set("X-Webhook-Signature", "sha256="+
			signAutomation([]byte("test-secret"), timestamp, signedID, signedBody))
		if mutate != nil {
			mutate(req)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Header().Get("Cache-Control") != "no-store, max-age=0" {
			t.Fatalf("status %d missing no-store header: %v", recorder.Code, recorder.Header())
		}
		return recorder
	}

	tests := []struct {
		name        string
		token       string
		rawQuery    string
		signedID    string
		signedBody  []byte
		requestBody []byte
		mutate      func(*http.Request)
		want        int
	}{
		{name: "missing query", token: tokenID, signedID: "evt", want: http.StatusBadRequest},
		{name: "duplicate query", token: tokenID, rawQuery: "delivery_id=evt&delivery_id=evt", signedID: "evt", want: http.StatusBadRequest},
		{name: "extra query", token: tokenID, rawQuery: "delivery_id=evt&other=1", signedID: "evt", want: http.StatusBadRequest},
		{name: "invalid encoding", token: tokenID, rawQuery: "delivery_id=%zz", signedID: "evt", want: http.StatusBadRequest},
		{name: "nonempty body", token: tokenID, rawQuery: "delivery_id=evt", signedID: "evt", requestBody: []byte(`{}`), want: http.StatusBadRequest},
		{name: "query and signed id mismatch", token: tokenID, rawQuery: "delivery_id=evt_query", signedID: "evt_header", want: http.StatusUnauthorized},
		{name: "signature not over empty body", token: tokenID, rawQuery: "delivery_id=evt", signedID: "evt", signedBody: []byte(`{}`), want: http.StatusUnauthorized},
		{name: "repeated delivery header", token: tokenID, rawQuery: "delivery_id=evt", signedID: "evt", mutate: func(req *http.Request) {
			req.Header[http.CanonicalHeaderKey("X-Webhook-Delivery")] = []string{"evt", "evt"}
		}, want: http.StatusUnauthorized},
		{name: "unknown completed delivery", token: tokenID, rawQuery: "delivery_id=evt_unknown", signedID: "evt_unknown", want: http.StatusNotFound},
		{name: "incomplete delivery", token: tokenID, rawQuery: "delivery_id=" + incompleteID, signedID: incompleteID, want: http.StatusNotFound},
		{name: "non automation provider", token: hashToken, rawQuery: "delivery_id=evt", signedID: "evt", want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := request(tc.token, tc.rawQuery, tc.signedID, tc.signedBody, tc.requestBody, tc.mutate)
			if response.Code != tc.want {
				t.Fatalf("got %d %s, want %d", response.Code, response.Body.String(), tc.want)
			}
		})
	}
}

func TestSupportedWebhookProvidersAreExplicit(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{ProviderAutomationV1, ProviderHashV1, "generic", "github", "stripe"} {
		if !IsSupportedProvider(provider) {
			t.Errorf("provider %q should be supported", provider)
		}
	}
	for _, provider := range []string{"", "automation", "automation-v2", "generci"} {
		if IsSupportedProvider(provider) {
			t.Errorf("provider %q should be rejected", provider)
		}
	}
}

func TestWebhookGenericHappyPath(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")

	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := []byte(`{"event":"order.created","id":"ord_1"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
	req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), body))
	req.Header.Set("X-Webhook-Delivery", "evt_42")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d %s", resp.StatusCode, buf)
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("dispatch count = %d, want 1", disp.calls.Load())
	}
	if string(disp.last) != string(body) {
		t.Fatalf("dispatched body mismatch")
	}
}

func TestWebhookSyncReturnsOutput(t *testing.T) {
	t.Parallel()
	r, _, j, _ := newTestReceiver(t, "shhh")
	// Add a SYNCHRONOUS webhook trigger.
	syncTok, _ := journal.NewTokenID()
	if _, err := j.CreateWebhookTrigger(context.Background(), "wf_1", syncTok, "cred_hmac", "generic", []byte(`{"sync":true,"timeout_seconds":5}`)); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := []byte(`{"q":"hello"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+syncTok, bytes.NewReader(body))
	req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), body))
	req.Header.Set("X-Webhook-Delivery", "sync_1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The fake DispatchSync returns succeeded + {"ok":true}, so the caller gets
	// 200 with the run result inline.
	if resp.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("sync webhook got %d %s, want 200", resp.StatusCode, buf)
	}
	var out struct {
		RunID  string          `json:"run_id"`
		Status string          `json:"status"`
		Output json.RawMessage `json:"output"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.RunID != "run_sync" || out.Status != "succeeded" || string(out.Output) != `{"ok":true}` {
		t.Fatalf("sync response = %+v", out)
	}
}

func TestParseSyncConfig(t *testing.T) {
	t.Parallel()
	if sc := parseSyncConfig([]byte(`{}`)); sc.Sync {
		t.Fatal("empty config should not be sync")
	}
	if sc := parseSyncConfig([]byte(`{"sync":true}`)); !sc.Sync || sc.TimeoutSeconds != 30 {
		t.Fatalf("default timeout wrong: %+v", sc)
	}
	if sc := parseSyncConfig([]byte(`{"sync":true,"timeout_seconds":999}`)); sc.TimeoutSeconds != 120 {
		t.Fatalf("timeout should clamp to 120, got %d", sc.TimeoutSeconds)
	}
}

func TestWebhookBadSignature(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := []byte(`{}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
	req.Header.Set("X-Webhook-Signature", "sha256=00000000")
	req.Header.Set("X-Webhook-Delivery", "evt_bad")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if disp.calls.Load() != 0 {
		t.Fatal("dispatch fired on bad signature")
	}
}

func TestWebhookDedupReplay(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := []byte(`{"id":"evt_dup"}`)
	sig := "sha256=" + sign([]byte("shhh"), body)

	post := func() int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
		req.Header.Set("X-Webhook-Signature", sig)
		req.Header.Set("X-Webhook-Delivery", "evt_dup")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if post() != http.StatusAccepted {
		t.Fatal("first delivery should be accepted")
	}
	if post() != http.StatusOK {
		t.Fatal("replay should be 200 (dedup)")
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("dispatch fired %d times, want 1", disp.calls.Load())
	}
}

func TestWebhookActiveLeaseRetriesAfterExpiry(t *testing.T) {
	t.Parallel()
	r, disp, j, tok := newTestReceiver(t, "shhh")
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	r.Now = func() time.Time { return clock }
	r.DeliveryLease = time.Minute

	trig, err := j.FindWebhookByToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"evt_crash_window"}`)
	if _, err := j.ClaimWebhookDelivery(context.Background(), trig.ID, "generic", "evt_crash_window", hashPayload(body), clock, time.Minute); err != nil {
		t.Fatal(err)
	}

	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	post := func() *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
		req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), body))
		req.Header.Set("X-Webhook-Delivery", "evt_crash_window")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	active := post()
	defer active.Body.Close()
	if active.StatusCode != http.StatusServiceUnavailable || active.Header.Get("Retry-After") != "60" {
		buf, _ := io.ReadAll(active.Body)
		t.Fatalf("active claim got %d retry-after=%q body=%s, want 503/60", active.StatusCode, active.Header.Get("Retry-After"), buf)
	}
	if disp.calls.Load() != 0 {
		t.Fatal("active duplicate dispatched a second run")
	}

	// Simulate the original receiver dying without dispatch/completion. Once
	// the lease expires, the exact provider retry must be able to recover it.
	clock = clock.Add(61 * time.Second)
	recovered := post()
	defer recovered.Body.Close()
	if recovered.StatusCode != http.StatusAccepted {
		buf, _ := io.ReadAll(recovered.Body)
		t.Fatalf("expired claim retry got %d %s, want 202", recovered.StatusCode, buf)
	}
	var recoveredReceipt deliveryReceipt
	if err := json.NewDecoder(recovered.Body).Decode(&recoveredReceipt); err != nil {
		t.Fatal(err)
	}
	if !recoveredReceipt.Accepted || recoveredReceipt.Deduped || recoveredReceipt.RunID != "run_async" {
		t.Fatalf("first durable receipt = %+v", recoveredReceipt)
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("recovered dispatch count = %d, want 1", disp.calls.Load())
	}

	completed := post()
	defer completed.Body.Close()
	if completed.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(completed.Body)
		t.Fatalf("completed replay got %d %s, want 200", completed.StatusCode, buf)
	}
	var completedReceipt deliveryReceipt
	if err := json.NewDecoder(completed.Body).Decode(&completedReceipt); err != nil {
		t.Fatal(err)
	}
	if !completedReceipt.Accepted || !completedReceipt.Deduped || completedReceipt.RunID != "run_async" {
		t.Fatalf("completed durable receipt = %+v", completedReceipt)
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("completed replay dispatched again; count=%d", disp.calls.Load())
	}
}

func TestWebhookDeliveryIDPayloadMismatchConflicts(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	post := func(body []byte) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
		req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), body))
		req.Header.Set("X-Webhook-Delivery", "evt_reused")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	first := post([]byte(`{"value":1}`))
	defer first.Body.Close()
	if first.StatusCode != http.StatusAccepted {
		t.Fatalf("first status = %d", first.StatusCode)
	}
	conflict := post([]byte(`{"value":2}`))
	defer conflict.Body.Close()
	if conflict.StatusCode != http.StatusConflict {
		buf, _ := io.ReadAll(conflict.Body)
		t.Fatalf("mismatched replay got %d %s, want 409", conflict.StatusCode, buf)
	}
	if disp.calls.Load() != 1 {
		t.Fatalf("mismatched replay dispatch count = %d, want 1", disp.calls.Load())
	}
}

func TestWebhookDispatchFailureReleasesClaim(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")
	disp.err = errors.New("dispatcher unavailable")
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := []byte(`{"id":"evt_retry_dispatch"}`)
	post := func() *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
		req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), body))
		req.Header.Set("X-Webhook-Delivery", "evt_retry_dispatch")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	failed := post()
	defer failed.Body.Close()
	if failed.StatusCode != http.StatusInternalServerError {
		t.Fatalf("failed dispatch status = %d", failed.StatusCode)
	}

	disp.err = nil
	retry := post()
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusAccepted {
		buf, _ := io.ReadAll(retry.Body)
		t.Fatalf("retry after dispatch failure got %d %s, want 202", retry.StatusCode, buf)
	}
	if disp.calls.Load() != 2 {
		t.Fatalf("dispatch attempts = %d, want 2", disp.calls.Load())
	}
}

func TestWebhookDisabledWorkflowDoesNotCompleteReceipt(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")
	disp.err = dispatcher.ErrWorkflowDisabled
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	body := []byte(`{"id":"evt_paused"}`)
	post := func() *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(body))
		req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), body))
		req.Header.Set("X-Webhook-Delivery", "evt_paused")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	paused := post()
	defer paused.Body.Close()
	if paused.StatusCode != http.StatusServiceUnavailable || paused.Header.Get("Retry-After") != "300" {
		t.Fatalf("paused workflow got %d retry-after=%q, want 503/300",
			paused.StatusCode, paused.Header.Get("Retry-After"))
	}

	// Once re-enabled, the same provider delivery can be accepted because the
	// disabled attempt released rather than completing its lease.
	disp.err = nil
	retry := post()
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusAccepted {
		buf, _ := io.ReadAll(retry.Body)
		t.Fatalf("retry after enable got %d %s, want 202", retry.StatusCode, buf)
	}
}

func TestWebhookUnknownToken(t *testing.T) {
	t.Parallel()
	r, _, _, _ := newTestReceiver(t, "x")
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/webhook/whk_doesnotexist", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestWebhookGitHubVerify(t *testing.T) {
	t.Parallel()
	body := []byte(`{"action":"opened"}`)
	key := []byte("secret123")
	good := "sha256=" + sign(key, body)
	if err := verifyGitHub(good, body, key); err != nil {
		t.Fatalf("good sig rejected: %v", err)
	}
	if err := verifyGitHub("sha256=00", body, key); err == nil {
		t.Fatal("bad sig accepted")
	}
	if err := verifyGitHub("md5=abc", body, key); err == nil {
		t.Fatal("non-sha256 prefix accepted")
	}
}

func TestWebhookStripeVerify(t *testing.T) {
	t.Parallel()
	body := []byte(`{"id":"evt_test"}`)
	key := []byte("whsec_xyz")
	now := time.Unix(1_700_000_000, 0)

	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d.", now.Unix())
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	header := fmt.Sprintf("t=%d,v1=%s", now.Unix(), sig)

	if err := verifyStripe(header, body, key, now); err != nil {
		t.Fatalf("good sig rejected: %v", err)
	}
	// Stale timestamp.
	if err := verifyStripe(header, body, key, now.Add(10*time.Minute)); err == nil {
		t.Fatal("stale timestamp accepted")
	}
	// Bad signature.
	bad := fmt.Sprintf("t=%d,v1=00000000", now.Unix())
	if err := verifyStripe(bad, body, key, now); err == nil {
		t.Fatal("bad sig accepted")
	}
}

func TestWebhookOversizeBodyRejected(t *testing.T) {
	t.Parallel()
	r, disp, _, tok := newTestReceiver(t, "shhh")
	router := chi.NewRouter()
	r.Mount(router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	huge := bytes.Repeat([]byte("a"), MaxBodyBytes+10)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/"+tok, bytes.NewReader(huge))
	req.Header.Set("X-Webhook-Signature", "sha256="+sign([]byte("shhh"), huge))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: status = %d, want 413", resp.StatusCode)
	}
	if disp.calls.Load() != 0 {
		t.Fatal("dispatch fired on oversize body")
	}
}

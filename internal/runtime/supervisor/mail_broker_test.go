package supervisor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
)

func mailBrokerFixture(t *testing.T, provider, workflowTenant, connectionTenant string, grant bool) (*Supervisor, *oauth.Store, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	j, db := oauthACLFixture(t, workflowTenant, connectionTenant)
	var authURL, tokenURL, scopes string
	switch provider {
	case "google":
		authURL = "https://accounts.google.com/o/oauth2/v2/auth"
		tokenURL = "https://oauth2.googleapis.com/token"
		scopes = "https://www.googleapis.com/auth/gmail.send"
	case "microsoft":
		authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
		tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		scopes = "https://graph.microsoft.com/Mail.Send"
	default:
		t.Fatal("unsupported fixture provider")
	}
	if _, err := db.ExecContext(ctx, `UPDATE oauth_providers SET auth_url=?, token_url=?, scopes=?, enabled=1 WHERE provider_id='google'`,
		authURL, tokenURL, scopes); err != nil {
		t.Fatal(err)
	}
	if provider == "microsoft" {
		if _, err := db.ExecContext(ctx, `UPDATE oauth_providers SET provider_id='microsoft', name='Microsoft' WHERE provider_id='google'`); err != nil {
			t.Fatal(err)
		}
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	identity := fmt.Sprintf("reactor-oauth-v1\x00connection-token\x00%d:%s\x00%d:%s\x00%d:%s",
		len(connectionTenant), connectionTenant, len(provider), provider, len("work"), "work")
	tokenJSON, err := json.Marshal(map[string]string{"access_token": "host-only-token", "scope": scopes})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := vault.EncryptForID(key, identity, tokenJSON)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET provider_id=?, token_encrypted=?, scopes=?, status='connected',
		token_access_mode='broker_only', legacy_raw_reason='' WHERE id='conn_abc'`, provider, sealed, scopes); err != nil {
		t.Fatal(err)
	}
	store := oauth.New(db, oauth.EngineSQLite, key)
	if _, err := j.RecordStepStartSeq(ctx, "run_1", "send", 1, 1, "mail-once", "mail-input"); err != nil {
		t.Fatal(err)
	}
	if grant && workflowTenant == connectionTenant {
		if err := j.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
			t.Fatal(err)
		}
	}
	return &Supervisor{WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j,
		OAuthTokens: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, store, db
}

func brokerMailRequest(t *testing.T, sup *Supervisor, request wire.MailSendRequest) (wire.MailSendReply, []byte) {
	t.Helper()
	var out bytes.Buffer
	disp := &dispatcher{sup: sup, enc: wire.NewEncoder(&out), writeMu: &sync.Mutex{}}
	f, err := wire.Wrap(1, 0, wire.KindMailSendRequest, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := disp.handleMailSendRequest(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Clone(out.Bytes())
	replyFrame, err := wire.NewDecoder(&out).Decode()
	if err != nil || replyFrame.Kind != wire.KindMailSendReply || replyFrame.Reply != f.ID {
		t.Fatalf("mail reply frame = %+v, %v", replyFrame, err)
	}
	var reply wire.MailSendReply
	if err := wire.Unwrap(replyFrame, &reply); err != nil {
		t.Fatal(err)
	}
	return reply, raw
}

func validMailRequest() wire.MailSendRequest {
	return wire.MailSendRequest{CredentialID: "oauth:conn_abc", StepName: "send", StepSeq: 1, StepAttempt: 1,
		IdempotencyKey: "mail-once", Message: wire.MailMessage{
			From: "me@example.com", To: []string{"customer@example.com"}, Subject: "Hello", Text: "customer body",
		}}
}

func TestMailBrokerSendsWithFixedProviderEndpointAndKeepsTokenHostSide(t *testing.T) {
	for _, tc := range []struct {
		provider, endpoint string
		status             int
		id                 string
	}{
		{"google", googleSendURL, 200, "msg_123"},
		{"microsoft", microsoftSendURL, 202, ""},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			sup, store, _ := mailBrokerFixture(t, tc.provider, "tenant-a", "tenant-a", true)
			calls := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.String() != tc.endpoint || r.Header.Get("Authorization") != "Bearer host-only-token" {
					t.Errorf("mail egress route = %s %s auth=%q", r.Method, r.URL, r.Header.Get("Authorization"))
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				if tc.provider == "google" {
					raw, _ := base64.URLEncoding.DecodeString(payload["raw"].(string))
					if !bytes.Contains(raw, []byte("To: customer@example.com")) || !bytes.Contains(raw, []byte("customer body")) {
						t.Errorf("Gmail payload missing message")
					}
				} else if payload["message"] == nil {
					t.Error("Microsoft payload missing message")
				}
				body := ""
				if tc.provider == "google" {
					body = `{"id":"msg_123"}`
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			reply, raw := brokerMailRequest(t, sup, validMailRequest())
			if reply.ErrorCode != "" || reply.Status != tc.status || reply.MessageID != tc.id || calls != 1 {
				t.Fatalf("mail reply = %+v, calls=%d", reply, calls)
			}
			replayed, _ := brokerMailRequest(t, sup, validMailRequest())
			if replayed != reply || calls != 1 {
				t.Fatalf("confirmed send replayed as %+v with %d provider calls", replayed, calls)
			}
			if bytes.Contains(raw, []byte("host-only-token")) || bytes.Contains(raw, []byte(tc.endpoint)) ||
				bytes.Contains(raw, []byte("customer body")) {
				t.Fatalf("mail response leaked token, URL, or body: %s", raw)
			}
			if allowed, err := store.RawTokenAllowed(context.Background(), "conn_abc", "tenant-a"); err != nil || allowed {
				t.Fatalf("fresh mail connection permits raw token: %v, %v", allowed, err)
			}
			if secret := fetchSecret(t, sup, "oauth:conn_abc"); !secret.NotFound || len(secret.Value) > 0 {
				t.Fatalf("mail connection released raw token: %+v", secret)
			}
			audit, err := sup.Journal.ListRuntimeSecretAccessForTenant(context.Background(), "tenant-a", 10, 0)
			if err != nil || len(audit) != 2 || audit[0].SecretRef != "oauth:conn_abc" || audit[1].SecretRef != "oauth:conn_abc" {
				t.Fatalf("mail audit = %+v, %v", audit, err)
			}
		})
	}
}

func TestMailBrokerDeniesWithoutAuthorityBeforeNetwork(t *testing.T) {
	for _, tc := range []struct {
		name, workflowTenant, connectionTenant, mode string
		grant                                        bool
		modify                                       func(*testing.T, *Supervisor, wire.MailSendRequest) wire.MailSendRequest
	}{
		{name: "no grant", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live"},
		{name: "cross tenant", workflowTenant: "tenant-a", connectionTenant: "tenant-b", mode: "live"},
		{name: "dry run", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "dry_run", grant: true},
		{name: "invalid ref", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live", grant: true,
			modify: func(_ *testing.T, _ *Supervisor, r wire.MailSendRequest) wire.MailSendRequest {
				r.CredentialID = "https://evil.example/send"
				return r
			}},
		{name: "missing Step", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live", grant: true,
			modify: func(_ *testing.T, _ *Supervisor, r wire.MailSendRequest) wire.MailSendRequest {
				r.StepName = ""
				return r
			}},
		{name: "forged Step attempt", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live", grant: true,
			modify: func(_ *testing.T, _ *Supervisor, r wire.MailSendRequest) wire.MailSendRequest {
				r.StepAttempt = 99
				return r
			}},
		{name: "missing Step key", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live", grant: true,
			modify: func(_ *testing.T, _ *Supervisor, r wire.MailSendRequest) wire.MailSendRequest {
				r.IdempotencyKey = ""
				return r
			}},
		{name: "oversize body", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live", grant: true,
			modify: func(_ *testing.T, _ *Supervisor, r wire.MailSendRequest) wire.MailSendRequest {
				r.Message.Text = strings.Repeat("x", maxMailRequestBytes)
				return r
			}},
		{name: "lost lease", workflowTenant: "tenant-a", connectionTenant: "tenant-a", mode: "live", grant: true,
			modify: func(t *testing.T, sup *Supervisor, r wire.MailSendRequest) wire.MailSendRequest {
				if err := sup.Journal.SetRunStatus(context.Background(), "run_1", "queued"); err != nil {
					t.Fatal(err)
				}
				claims, err := sup.Journal.ClaimQueuedRuns(context.Background(), "mail-worker", 1, time.Minute)
				if err != nil || len(claims) != 1 {
					t.Fatalf("claim = %+v, %v", claims, err)
				}
				return r
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, _, _ := mailBrokerFixture(t, "google", tc.workflowTenant, tc.connectionTenant, tc.grant)
			sup.Mode = tc.mode
			request := validMailRequest()
			if tc.modify != nil {
				request = tc.modify(t, sup, request)
			}
			calls := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("must not dial")
			})}
			reply, raw := brokerMailRequest(t, sup, request)
			if calls != 0 || reply.ErrorCode == "" || bytes.Contains(raw, []byte("host-only-token")) {
				t.Fatalf("unauthorized mail dialed: reply=%+v calls=%d", reply, calls)
			}
		})
	}
}

func TestMailBrokerAuditFailureAndAmbiguousPOST(t *testing.T) {
	sup, _, _ := mailBrokerFixture(t, "google", "tenant-a", "tenant-a", true)
	calls := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("ambiguous transport failure with private bytes")
	})}
	reply, raw := brokerMailRequest(t, sup, validMailRequest())
	if calls != 1 || reply.ErrorCode != "ambiguous" || bytes.Contains(raw, []byte("private bytes")) {
		t.Fatalf("ambiguous POST retried or leaked: reply=%+v calls=%d raw=%s", reply, calls, raw)
	}
	reply, _ = brokerMailRequest(t, sup, validMailRequest())
	if reply.ErrorCode != "ambiguous" || calls != 1 {
		t.Fatalf("ambiguous replay resent mail: reply=%+v calls=%d", reply, calls)
	}
	sup, _, db := mailBrokerFixture(t, "google", "tenant-a", "tenant-a", true)
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not dial when audit unavailable")
	})}
	if _, err := db.ExecContext(context.Background(), `DROP TABLE runtime_secret_access_audit`); err != nil {
		t.Fatal(err)
	}
	reply, _ = brokerMailRequest(t, sup, validMailRequest())
	if reply.ErrorCode != "audit_unavailable" || calls != 1 {
		t.Fatalf("audit failure sent mail: reply=%+v calls=%d", reply, calls)
	}
}

type mailResolverHook struct {
	*oauth.Store
	beforeCurrent func(context.Context)
	currentCalls  int
}

func (h *mailResolverHook) MailBrokerSessionCurrent(ctx context.Context, session oauth.MailBrokerSession) (bool, error) {
	if h.currentCalls == 0 && h.beforeCurrent != nil {
		h.beforeCurrent(ctx)
	}
	h.currentCalls++
	return h.Store.MailBrokerSessionCurrent(ctx, session)
}

func TestMailBrokerRechecksAuthorityImmediatelyBeforePOST(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, context.Context, *Supervisor, *sql.DB)
	}{
		{"grant revoked", func(t *testing.T, ctx context.Context, sup *Supervisor, _ *sql.DB) {
			if err := sup.Journal.RevokeSecret(ctx, "wf_1", "oauth:conn_abc"); err != nil {
				t.Fatal(err)
			}
		}},
		{"run stopped", func(t *testing.T, ctx context.Context, sup *Supervisor, _ *sql.DB) {
			if err := sup.Journal.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
				t.Fatal(err)
			}
		}},
		{"connection revoked", func(t *testing.T, ctx context.Context, _ *Supervisor, db *sql.DB) {
			if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET status='revoked' WHERE id='conn_abc'`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, store, db := mailBrokerFixture(t, "google", "tenant-a", "tenant-a", true)
			sup.OAuthTokens = &mailResolverHook{Store: store, beforeCurrent: func(ctx context.Context) {
				tc.change(t, ctx, sup, db)
			}}
			calls := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, errors.New("authority changed before egress")
			})}
			reply, raw := brokerMailRequest(t, sup, validMailRequest())
			if calls != 0 || reply.ErrorCode == "" || bytes.Contains(raw, []byte("host-only-token")) {
				t.Fatalf("stale authority sent mail: reply=%+v calls=%d", reply, calls)
			}
			var intents int
			if err := db.QueryRow(`SELECT COUNT(*) FROM mail_send_intents`).Scan(&intents); err != nil || intents != 0 {
				t.Fatalf("preflight failure admitted mail intent: %d, %v", intents, err)
			}
		})
	}
}

func TestMailBrokerRejectsOtherOAuthProviderBeforePOST(t *testing.T) {
	sup, _, db := mailBrokerFixture(t, "google", "tenant-a", "tenant-a", true)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO oauth_providers
		(provider_id,name,auth_url,token_url,scopes,enabled) VALUES
		('slack','Slack','https://slack.com/oauth/v2/authorize','https://slack.com/api/oauth.v2.access','chat:write',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET provider_id='slack' WHERE id='conn_abc'`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not dial")
	})}
	reply, _ := brokerMailRequest(t, sup, validMailRequest())
	if reply.ErrorCode != "connection_unavailable" || calls != 0 {
		t.Fatalf("non-mail OAuth provider entered POST route: %+v, calls=%d", reply, calls)
	}
}

func TestMailBrokerBoundsResponseAndDoesNotFollowRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		header     http.Header
	}{
		{"oversize response", strings.Repeat("x", maxMailResponseBytes+1), http.StatusOK, make(http.Header)},
		{"redirect", "redirect body", http.StatusFound, http.Header{"Location": []string{"https://attacker.example/collect"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, _, db := mailBrokerFixture(t, "google", "tenant-a", "tenant-a", true)
			calls := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: tc.status, Header: tc.header,
					Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})}
			reply, raw := brokerMailRequest(t, sup, validMailRequest())
			if reply.ErrorCode != "ambiguous" || calls != 1 || bytes.Contains(raw, []byte("attacker.example")) ||
				bytes.Contains(raw, []byte("host-only-token")) || bytes.Contains(raw, []byte("redirect body")) {
				t.Fatalf("unsafe provider response: reply=%+v calls=%d raw=%s", reply, calls, raw)
			}
			var status, provider, connection string
			if err := db.QueryRow(`SELECT status, target_provider_id, target_connection_id FROM mail_send_intents WHERE run_id='run_1'`).
				Scan(&status, &provider, &connection); err != nil || status != "admitted" || provider != "google" || connection != "conn_abc" {
				t.Fatalf("uncertain response intent = %q, target=%q/%q, %v", status, provider, connection, err)
			}
		})
	}
}

func TestMailBrokerAcceptedSendSurvivesPostSendFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, context.Context, *Supervisor, *sql.DB)
	}{
		{"grant revoked", func(t *testing.T, ctx context.Context, sup *Supervisor, _ *sql.DB) {
			if err := sup.Journal.RevokeSecret(ctx, "wf_1", "oauth:conn_abc"); err != nil {
				t.Fatal(err)
			}
		}},
		{"run stopped", func(t *testing.T, ctx context.Context, sup *Supervisor, _ *sql.DB) {
			if err := sup.Journal.SetRunStatus(ctx, "run_1", "suspended"); err != nil {
				t.Fatal(err)
			}
		}},
		{"connection revoked", func(t *testing.T, ctx context.Context, _ *Supervisor, db *sql.DB) {
			if _, err := db.ExecContext(ctx, `UPDATE oauth_connections SET status='revoked' WHERE id='conn_abc'`); err != nil {
				t.Fatal(err)
			}
		}},
		{"permit completion failed", func(t *testing.T, ctx context.Context, _ *Supervisor, db *sql.DB) {
			if _, err := db.ExecContext(ctx, `DROP TABLE provider_shared_account_permits`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, _, db := mailBrokerFixture(t, "google", "tenant-a", "tenant-a", true)
			calls := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				tc.change(t, r.Context(), sup, db)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"id":"accepted_123"}`)), Request: r}, nil
			})}
			reply, raw := brokerMailRequest(t, sup, validMailRequest())
			if reply.ErrorCode != "ambiguous" || calls != 1 || bytes.Contains(raw, []byte("host-only-token")) {
				t.Fatalf("post-send failure became retryable or leaked: %+v calls=%d raw=%s", reply, calls, raw)
			}
			var status, messageID string
			if err := db.QueryRow(`SELECT status, message_id FROM mail_send_intents WHERE run_id='run_1'`).Scan(&status, &messageID); err != nil || status != "confirmed" || messageID != "accepted_123" {
				t.Fatalf("accepted send confirmation = %q %q, %v", status, messageID, err)
			}
		})
	}
}

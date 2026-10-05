package supervisor

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/vault"
)

func genericBrokerFixture(t *testing.T, workflowTenant, connectionTenant string, approve, grant bool) (*Supervisor, *oauth.Store, *sql.DB) {
	t.Helper()
	j, db := oauthACLFixture(t, workflowTenant, connectionTenant)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	identity := fmt.Sprintf("reactor-oauth-v1\x00connection-token\x00%d:%s\x00%d:%s\x00%d:%s",
		len(connectionTenant), connectionTenant, len("google"), "google", len("work"), "work")
	sealed, err := vault.EncryptForID(key, identity, []byte(`{"access_token":"super-secret-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE oauth_connections SET token_encrypted=? WHERE id='conn_abc'`, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE oauth_providers SET auth_url='https://login.acme.example/authorize',
		token_url='https://login.acme.example/token', enabled=1 WHERE provider_id='google'`); err != nil {
		t.Fatal(err)
	}
	store := oauth.New(db, oauth.EngineSQLite, key)
	if approve {
		if _, err := store.ApproveBrokerPolicy(context.Background(), connectionTenant, "conn_abc", "admin", 0,
			"https://api.acme.example", "/v1/accounts", "GET"); err != nil {
			t.Fatal(err)
		}
	}
	if grant && workflowTenant == connectionTenant {
		if err := j.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
			t.Fatal(err)
		}
	}
	sup := &Supervisor{WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j,
		OAuthTokens: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return sup, store, db
}

func TestGenericBrokerHostWireKeepsTokenAndOriginHostSide(t *testing.T) {
	t.Parallel()
	sup, store, _ := genericBrokerFixture(t, "tenant-a", "tenant-a", true, true)
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "api.acme.example" ||
			r.URL.RequestURI() != "/v1/accounts/123?fields=id%2Cname" ||
			r.Header.Get("Authorization") != "Bearer super-secret-token" {
			t.Fatalf("unsafe generic broker request: URL=%s auth=%q", r.URL, r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"id":"123"}`)), Request: r}, nil
	})}
	reply, raw := brokerRequest(t, sup, wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET",
		Path: "/v1/accounts/123?fields=id%2Cname"})
	if requests != 1 || reply.ErrorCode != "" || reply.Status != 200 || string(reply.Body) != `{"id":"123"}` {
		t.Fatalf("generic broker reply=%+v requests=%d", reply, requests)
	}
	if bytes.Contains(raw, []byte("super-secret-token")) || bytes.Contains(raw, []byte("api.acme.example")) {
		t.Fatalf("host-only credential/origin crossed wire: %q", raw)
	}
	if allowed, err := store.RawTokenAllowed(context.Background(), "conn_abc", "tenant-a"); err != nil || allowed {
		t.Fatalf("approved connection still raw-token eligible: %v, %v", allowed, err)
	}
	if secret := fetchSecret(t, sup, "oauth:conn_abc"); !secret.NotFound || len(secret.Value) != 0 {
		t.Fatalf("broker-only SecretFetch released raw token: %+v", secret)
	}
	audit, err := sup.Journal.ListRuntimeSecretAccessForTenant(context.Background(), "tenant-a", 10, 0)
	if err != nil || len(audit) != 1 || audit[0].PolicyRevision != 1 || audit[0].SecretRef != "oauth:conn_abc" {
		t.Fatalf("broker review audit=%+v err=%v", audit, err)
	}
}

func TestGenericBrokerDeniesUnsafeContextsAndPaths(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, workflowTenant, connectionTenant, mode, path string
		approve, grant                                     bool
	}{
		{"unreviewed", "tenant-a", "tenant-a", "live", "/v1/accounts/1", false, true},
		{"no grant", "tenant-a", "tenant-a", "live", "/v1/accounts/1", true, false},
		{"cross tenant", "tenant-a", "tenant-b", "live", "/v1/accounts/1", true, false},
		{"dry run", "tenant-a", "tenant-a", "dry_run", "/v1/accounts/1", true, true},
		{"prefix sibling", "tenant-a", "tenant-a", "live", "/v1/accountsx", true, true},
		{"encoded traversal", "tenant-a", "tenant-a", "live", "/v1/accounts/%2e%2e/private", true, true},
		{"absolute URL", "tenant-a", "tenant-a", "live", "https://evil.test/v1/accounts", true, true},
		{"query authority", "tenant-a", "tenant-a", "live", "//evil.test/v1/accounts", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup, _, _ := genericBrokerFixture(t, tc.workflowTenant, tc.connectionTenant, tc.approve, tc.grant)
			sup.Mode = tc.mode
			calls := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				return nil, fmt.Errorf("should not dial")
			})}
			reply, _ := brokerRequest(t, sup, wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: tc.path})
			if calls != 0 || reply.ErrorCode == "" || len(reply.Body) != 0 {
				t.Fatalf("unsafe context dialed %d times: %+v", calls, reply)
			}
		})
	}
}

type policyChangingResolver struct {
	*oauth.Store
	hook   func(context.Context, oauth.BrokerSession)
	checks int
}

func (r *policyChangingResolver) BrokerPolicyCurrent(ctx context.Context, s oauth.BrokerSession) (bool, error) {
	r.checks++
	if r.hook != nil {
		r.hook(ctx, s)
	}
	return r.Store.BrokerPolicyCurrent(ctx, s)
}

func TestGenericBrokerPolicyEditBeforeEgressAndDuringResponse(t *testing.T) {
	t.Parallel()
	for _, duringResponse := range []bool{false, true} {
		name := "before egress"
		if duringResponse {
			name = "during response"
		}
		t.Run(name, func(t *testing.T) {
			sup, store, _ := genericBrokerFixture(t, "tenant-a", "tenant-a", true, true)
			resolver := &policyChangingResolver{Store: store}
			sup.OAuthTokens = resolver
			calls := 0
			change := func(ctx context.Context) {
				t.Helper()
				if _, err := store.ApproveBrokerPolicy(ctx, "tenant-a", "conn_abc", "second-admin", 1,
					"https://other.acme.example", "/v2", "GET"); err != nil {
					t.Fatal(err)
				}
			}
			if !duringResponse {
				resolver.hook = func(ctx context.Context, _ oauth.BrokerSession) {
					if resolver.checks == 1 {
						change(ctx)
					}
				}
			}
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if duringResponse {
					change(r.Context())
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"secret":"provider-data"}`)), Request: r}, nil
			})}
			reply, raw := brokerRequest(t, sup, wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/v1/accounts"})
			wantCalls := 0
			if duringResponse {
				wantCalls = 1
			}
			if calls != wantCalls || reply.ErrorCode != "denied" || bytes.Contains(raw, []byte("provider-data")) {
				t.Fatalf("stale policy reply=%+v calls=%d", reply, calls)
			}
		})
	}
}

func TestGenericBrokerGrantRevocationBeforeEgressAndDuringResponse(t *testing.T) {
	t.Parallel()
	for _, duringResponse := range []bool{false, true} {
		name := "before egress"
		if duringResponse {
			name = "during response"
		}
		t.Run(name, func(t *testing.T) {
			sup, store, _ := genericBrokerFixture(t, "tenant-a", "tenant-a", true, true)
			resolver := &policyChangingResolver{Store: store}
			sup.OAuthTokens = resolver
			calls := 0
			revoke := func(ctx context.Context) {
				t.Helper()
				if err := sup.Journal.RevokeSecret(ctx, "wf_1", "oauth:conn_abc"); err != nil {
					t.Fatal(err)
				}
			}
			if !duringResponse {
				resolver.hook = func(ctx context.Context, _ oauth.BrokerSession) {
					if resolver.checks == 1 {
						revoke(ctx)
					}
				}
			}
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if duringResponse {
					revoke(r.Context())
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"secret":"provider-data"}`)), Request: r}, nil
			})}
			reply, raw := brokerRequest(t, sup, wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/v1/accounts"})
			wantCalls := 0
			if duringResponse {
				wantCalls = 1
			}
			if calls != wantCalls || reply.ErrorCode != "denied" || bytes.Contains(raw, []byte("provider-data")) {
				t.Fatalf("revoked grant reply=%+v calls=%d", reply, calls)
			}
		})
	}
}

func TestGenericBrokerCooldownAndSharedBudget(t *testing.T) {
	t.Parallel()
	sup, _, db := genericBrokerFixture(t, "tenant-a", "tenant-a", true, true)
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"120"}},
			Body: io.NopCloser(strings.NewReader("private-provider-error")), Request: r}, nil
	})}
	request := wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/v1/accounts"}
	first, raw := brokerRequest(t, sup, request)
	if first.ErrorCode != "upstream_status" || first.Status != 429 || first.RetryAfterMs != 120000 ||
		bytes.Contains(raw, []byte("private-provider-error")) {
		t.Fatalf("generic 429 reply=%+v", first)
	}
	second, _ := brokerRequest(t, sup, request)
	if requests != 1 || second.ErrorCode != "rate_limited" || second.RetryAfterMs <= 0 {
		t.Fatalf("cooldown not enforced: %+v requests=%d", second, requests)
	}
	// The durable shared budget key is tenant+provider, not a child value.
	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM provider_shared_account_permits WHERE tenant_id='tenant-a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("shared permit receipt count=%d err=%v", count, err)
	}
}

func TestGenericBrokerRejectsStaleLeaseAndResponseAfterExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sup, _, _ := genericBrokerFixture(t, "tenant-a", "tenant-a", true, true)
	sup.RunID = "run_generic_lease"
	if err := sup.Journal.CreateQueuedRun(ctx, sup.RunID, "wf_1", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	claim, err := sup.Journal.ClaimQueuedRuns(ctx, "worker-a", 1, time.Minute)
	if err != nil || len(claim) != 1 {
		t.Fatalf("claim=%+v err=%v", claim, err)
	}
	calls := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if err := sup.Journal.ExtendLease(ctx, sup.RunID, claim[0].Owner, -time.Minute); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"private":"response"}`)), Request: r}, nil
	})}
	request := wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/v1/accounts"}
	if reply, _ := brokerRequest(t, sup, request); reply.ErrorCode != "denied" || calls != 0 {
		t.Fatalf("local child used leased run: %+v calls=%d", reply, calls)
	}
	sup.LeaseOwner = claim[0].Owner
	if reply, raw := brokerRequest(t, sup, request); reply.ErrorCode != "denied" || calls != 1 ||
		bytes.Contains(raw, []byte("response")) {
		t.Fatalf("expired response released: %+v calls=%d", reply, calls)
	}
	if n, err := sup.Journal.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("reap=%d err=%v", n, err)
	}
	replacement, err := sup.Journal.ClaimQueuedRuns(ctx, "worker-b", 1, time.Minute)
	if err != nil || len(replacement) != 1 {
		t.Fatalf("replacement claim=%+v err=%v", replacement, err)
	}
	if reply, _ := brokerRequest(t, sup, request); reply.ErrorCode != "denied" || calls != 1 {
		t.Fatalf("replaced worker egress: %+v calls=%d", reply, calls)
	}
}

func TestGenericBrokerRejectsRedirectAndOversizedResponse(t *testing.T) {
	t.Parallel()
	sup, _, _ := genericBrokerFixture(t, "tenant-a", "tenant-a", true, true)
	count := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		count++
		if count == 1 {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://evil.test/steal"}},
				Body: io.NopCloser(strings.NewReader("private-error")), Request: r}, nil
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxConnectorResponseBytes+1))), Request: r}, nil
	})}
	request := wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/v1/accounts"}
	first, raw := brokerRequest(t, sup, request)
	if first.ErrorCode != "upstream_status" || first.Status != 302 ||
		bytes.Contains(raw, []byte("private-error")) || bytes.Contains(raw, []byte("evil.test")) {
		t.Fatalf("redirect leaked: %+v", first)
	}
	second, raw := brokerRequest(t, sup, request)
	if second.ErrorCode != "response_too_large" || len(second.Body) != 0 || len(raw) > 4096 {
		t.Fatalf("oversized body leaked: %+v wire bytes=%d", second, len(raw))
	}
}

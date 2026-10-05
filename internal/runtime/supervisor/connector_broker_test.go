package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
)

type brokerRoundTrip func(*http.Request) (*http.Response, error)

func (f brokerRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func brokerFixture(t *testing.T, workflowTenant, connectionTenant string) *Supervisor {
	t.Helper()
	j, db := oauthACLFixture(t, workflowTenant, connectionTenant)
	if _, err := db.Exec(`INSERT INTO oauth_providers (provider_id, name, auth_url, token_url, enabled)
		VALUES ('salesforce', 'Salesforce', 'https://login.salesforce.com/auth', 'https://login.salesforce.com/token', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE oauth_connections SET provider_id = 'salesforce', status = 'connected' WHERE id = 'conn_abc'`); err != nil {
		t.Fatal(err)
	}
	return &Supervisor{
		WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j,
		OAuthTokens: stubOAuthResolver{token: "super-secret-token", wantTenant: workflowTenant,
			provider: "salesforce", origin: "https://acme.my.salesforce.com"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func brokerRequest(t *testing.T, sup *Supervisor, body wire.ConnectorRequest) (wire.ConnectorReply, []byte) {
	t.Helper()
	var buf bytes.Buffer
	disp := &dispatcher{sup: sup, enc: wire.NewEncoder(&buf), writeMu: &sync.Mutex{}}
	req, err := wire.Wrap(1, 0, wire.KindConnectorRequest, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := disp.handleConnectorRequest(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Clone(buf.Bytes())
	frame, err := wire.NewDecoder(&buf).Decode()
	if err != nil {
		t.Fatal(err)
	}
	var reply wire.ConnectorReply
	if err := wire.Unwrap(frame, &reply); err != nil {
		t.Fatal(err)
	}
	return reply, raw
}

type reconnectingSalesforceResolver struct {
	stubOAuthResolver
	reconnected  bool
	afterSession bool
}

func (s *reconnectingSalesforceResolver) SalesforceBrokerSession(ctx context.Context, connectionID, tenantID string) (string, string, string, error) {
	token, origin, key, err := s.stubOAuthResolver.SalesforceBrokerSession(ctx, connectionID, tenantID)
	if s.afterSession {
		s.reconnected = true
	}
	return token, origin, key, err
}

func (s *reconnectingSalesforceResolver) SalesforceBrokerSessionCurrent(ctx context.Context, connectionID, tenantID, token, origin, key string) (bool, error) {
	current, err := s.stubOAuthResolver.SalesforceBrokerSessionCurrent(ctx, connectionID, tenantID, token, origin, key)
	return current && !s.reconnected, err
}

func TestSalesforceBrokerRejectsReconnectedSessionBeforeEgressAndReply(t *testing.T) {
	for _, tc := range []struct {
		name         string
		afterSession bool
		wantRequests int
	}{
		{"before egress", true, 0},
		{"during response", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup := brokerFixture(t, "tenant-a", "tenant-a")
			if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
				t.Fatal(err)
			}
			resolver := &reconnectingSalesforceResolver{
				stubOAuthResolver: stubOAuthResolver{token: "old-secret-token", wantTenant: "tenant-a",
					provider: "salesforce", origin: "https://acme.my.salesforce.com"},
				afterSession: tc.afterSession,
			}
			sup.OAuthTokens = resolver
			requests := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				requests++
				resolver.reconnected = true
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(`{"private":"old-account"}`)), Request: r}, nil
			})}
			request := wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/"}
			reply, raw := brokerRequest(t, sup, request)
			if requests != tc.wantRequests || reply.ErrorCode != "denied" || reply.Status != 0 || len(reply.Body) != 0 ||
				bytes.Contains(raw, []byte("old-account")) || bytes.Contains(raw, []byte("old-secret-token")) {
				t.Fatalf("reconnected session leaked: requests=%d reply=%+v", requests, reply)
			}
			// Denied calls still complete both permits. Three follow-ups exceed
			// the two-slot concurrency cap if even one permit stays active.
			resolver.afterSession = false
			for i := 0; i < 3; i++ {
				resolver.reconnected = false
				reply, _ = brokerRequest(t, sup, request)
				if reply.ErrorCode != "denied" || requests != tc.wantRequests+i+1 {
					t.Fatalf("follow-up %d did not clear permit: requests=%d reply=%+v", i, requests, reply)
				}
			}
		})
	}
}

func TestSalesforceBrokerPathRejectsOriginAndTraversal(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"", "https://evil.test/services/data/v62.0/", "//evil.test/services/data/v62.0/",
		"/services/data/../oauth2/token", "/services/data/./v62.0/",
		"/services/data/%2e%2e/oauth2/token", "/services/data/%2F%2Fevil.test",
		"/services/data/%252e%252e/", "/services/data/\\evil.test",
		"/services/data/v62.0#fragment", "/services/data/v62.0?x=1#fragment",
		"/services/data/v62.0\r\nX-Evil: yes", "/services/data/v62.0\x00",
		"/services/data/v62.0?x=" + strings.Repeat("a", maxConnectorPathBytes),
	} {
		if got, err := salesforceBrokerPath(bad); err == nil || got != "" {
			t.Errorf("accepted unsafe path %q as %q", bad, got)
		}
	}
	for _, good := range []string{
		"/services/data/v62.0/", "/services/data/v62.0/query?q=SELECT+Id+FROM+Account",
	} {
		if got, err := salesforceBrokerPath(good); err != nil || got != good {
			t.Errorf("safe path %q = %q, %v", good, got, err)
		}
	}
}

func TestSalesforceBrokerBindsCredentialToCurrentOriginAndPermit(t *testing.T) {
	t.Parallel()
	sup := brokerFixture(t, "tenant-a", "tenant-a")
	if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Scheme != "https" || r.URL.Host != "acme.my.salesforce.com" ||
			r.URL.EscapedPath() != "/services/data/v62.0/sobjects/Account" ||
			r.URL.Query().Get("fields") != "Id,Name" ||
			r.Header.Get("Authorization") != "Bearer super-secret-token" {
			t.Fatalf("broker sent unsafe request: URL=%s auth=%q", r.URL, r.Header.Get("Authorization"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"id":"001"}`)), Request: r}, nil
	})}
	reply, raw := brokerRequest(t, sup, wire.ConnectorRequest{
		CredentialID: "oauth:conn_abc", Method: "GET",
		Path: "/services/data/v62.0/sobjects/Account?fields=Id,Name",
	})
	if requests != 1 || reply.Status != http.StatusOK || reply.ErrorCode != "" || string(reply.Body) != `{"id":"001"}` {
		t.Fatalf("broker reply = %+v after %d requests", reply, requests)
	}
	if bytes.Contains(raw, []byte("super-secret-token")) ||
		bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte("super-secret-token")))) {
		t.Fatal("OAuth token escaped over workflow wire")
	}
}

func TestSalesforceBrokerDeniesUngrantableContexts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, workflowTenant, connectionTenant, mode, origin string
		grant                                                bool
	}{
		{"no grant", "tenant-a", "tenant-a", "live", "https://acme.my.salesforce.com", false},
		{"cross tenant", "tenant-a", "tenant-b", "live", "https://acme.my.salesforce.com", true},
		{"dry run", "tenant-a", "tenant-a", "dry_run", "https://acme.my.salesforce.com", true},
		{"untrusted origin", "tenant-a", "tenant-a", "live", "https://acme.my.salesforce.com.evil.test", true},
		{"private origin", "tenant-a", "tenant-a", "live", "https://127.0.0.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sup := brokerFixture(t, tc.workflowTenant, tc.connectionTenant)
			sup.Mode = tc.mode
			sup.OAuthTokens = stubOAuthResolver{token: "super-secret-token", wantTenant: tc.workflowTenant,
				provider: "salesforce", origin: tc.origin}
			if tc.grant && tc.workflowTenant == tc.connectionTenant {
				if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
					t.Fatal(err)
				}
			}
			requests := 0
			sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
				requests++
				return nil, errors.New("should not dial")
			})}
			reply, _ := brokerRequest(t, sup, wire.ConnectorRequest{
				CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/",
			})
			if requests != 0 || reply.ErrorCode == "" || len(reply.Body) != 0 {
				t.Fatalf("unsafe context dialed %d times, reply %+v", requests, reply)
			}
		})
	}
}

func TestSalesforceBrokerDoesNotFollowRedirectOrReflectErrors(t *testing.T) {
	t.Parallel()
	sup := brokerFixture(t, "tenant-a", "tenant-a")
	if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusFound,
			Header: http.Header{"Location": []string{"https://evil.test/steal"}},
			Body:   io.NopCloser(strings.NewReader("secret-provider-error")), Request: r}, nil
	})}
	reply, raw := brokerRequest(t, sup, wire.ConnectorRequest{
		CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/?secret_query=private",
	})
	if requests != 1 || reply.Status != http.StatusFound || reply.ErrorCode != "upstream_status" || len(reply.Body) != 0 {
		t.Fatalf("redirect reply = %+v after %d requests", reply, requests)
	}
	for _, secret := range []string{"super-secret-token", "secret_query", "private", "secret-provider-error", "evil.test"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("broker reply leaked %q", secret)
		}
	}
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("super-secret-token secret_query=private upstream detail")
	})}
	reply, raw = brokerRequest(t, sup, wire.ConnectorRequest{
		CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/?secret_query=private",
	})
	if reply.ErrorCode != "upstream_unavailable" || len(reply.Body) != 0 ||
		bytes.Contains(raw, []byte("super-secret-token")) || bytes.Contains(raw, []byte("secret_query")) ||
		bytes.Contains(raw, []byte("upstream detail")) {
		t.Fatalf("broker leaked transport error: %+v, wire=%q", reply, raw)
	}
}

func TestSalesforceBrokerCapsResponseAndPersistsCooldown(t *testing.T) {
	t.Parallel()
	sup := brokerFixture(t, "tenant-a", "tenant-a")
	if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxConnectorResponseBytes+1))), Request: r}, nil
		}
		return &http.Response{StatusCode: http.StatusTooManyRequests,
			Header: http.Header{"Retry-After": []string{"120"}},
			Body:   io.NopCloser(strings.NewReader("provider-private-body")), Request: r}, nil
	})}
	request := wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/"}
	first, _ := brokerRequest(t, sup, request)
	if first.ErrorCode != "response_too_large" || len(first.Body) != 0 {
		t.Fatalf("oversized response escaped: %+v", first)
	}
	second, raw := brokerRequest(t, sup, request)
	if second.Status != http.StatusTooManyRequests || second.RetryAfterMs != 120000 || bytes.Contains(raw, []byte("provider-private-body")) {
		t.Fatalf("429 reply = %+v", second)
	}
	third, _ := brokerRequest(t, sup, request)
	if requests != 2 || third.ErrorCode != "rate_limited" || third.RetryAfterMs <= 0 {
		t.Fatalf("cooldown failed: reply %+v after %d requests", third, requests)
	}
}

func TestSalesforceBrokerDeniesWhenAccountConcurrencyIsExhausted(t *testing.T) {
	t.Parallel()
	sup := brokerFixture(t, "tenant-a", "tenant-a")
	if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	policy := journal.ProviderPermitPolicy{RequestsPerMinute: 30, MaxConcurrent: 2}
	for range 2 {
		if _, err := sup.Journal.AcquireProviderPermit(context.Background(), "tenant-a", "conn_abc", policy); err != nil {
			t.Fatal(err)
		}
	}
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("should not dial")
	})}
	reply, _ := brokerRequest(t, sup, wire.ConnectorRequest{
		CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/",
	})
	if requests != 0 || reply.ErrorCode != "rate_limited" || reply.RetryAfterMs <= 0 {
		t.Fatalf("exhausted permit dialed %d times, reply %+v", requests, reply)
	}
}

func TestSalesforceBrokerSharesOrgBudgetAcrossConnections(t *testing.T) {
	t.Parallel()
	j, db := oauthACLFixture(t, "tenant-a", "tenant-a")
	if _, err := db.Exec(`INSERT INTO oauth_providers (provider_id, name, auth_url, token_url, enabled)
		VALUES ('salesforce', 'Salesforce', 'https://login.salesforce.com/auth', 'https://login.salesforce.com/token', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE oauth_connections SET provider_id = 'salesforce', status = 'connected' WHERE id = 'conn_abc'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO oauth_connections
		(id, tenant_id, provider_id, name, token_encrypted, status)
		VALUES ('conn_other', 'tenant-a', 'salesforce', 'other', ?, 'connected')`, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if err := j.GrantSecret(context.Background(), "wf_1", "oauth:conn_other", "admin", ""); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("a", 64)
	sup := &Supervisor{
		WorkflowSlug: "mailer", RunID: "run_1", Mode: "live", Journal: j,
		OAuthTokens: stubOAuthResolver{token: "super-secret-token", wantTenant: "tenant-a",
			provider: "salesforce", origin: "https://acme.my.salesforce.com", accountKey: key},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	policy := journal.ProviderPermitPolicy{RequestsPerMinute: 30, MaxConcurrent: 2}
	for _, conn := range []string{"conn_abc", "conn_other"} {
		permit, err := j.AcquireSharedProviderPermit(context.Background(), "tenant-a", conn, "salesforce", key, policy)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = j.CompleteSharedProviderPermit(context.Background(), permit, 0) }()
	}
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("should not dial")
	})}
	reply, _ := brokerRequest(t, sup, wire.ConnectorRequest{
		CredentialID: "oauth:conn_other", Method: "GET", Path: "/services/data/v62.0/",
	})
	if requests != 0 || reply.ErrorCode != "rate_limited" || reply.RetryAfterMs <= 0 {
		t.Fatalf("org budget exhausted across connections, dialed %d times, reply %+v", requests, reply)
	}

	sup.OAuthTokens = stubOAuthResolver{token: "super-secret-token", wantTenant: "tenant-a",
		provider: "salesforce", origin: "https://acme.my.salesforce.com", accountKey: "workflow-input"}
	reply, _ = brokerRequest(t, sup, wire.ConnectorRequest{
		CredentialID: "oauth:conn_other", Method: "GET", Path: "/services/data/v62.0/",
	})
	if requests != 0 || reply.ErrorCode != "permit_unavailable" {
		t.Fatalf("invalid host account key allowed egress: dialed %d times, reply %+v", requests, reply)
	}
}

func TestSalesforceBrokerDeniesExpiredAndReplacedWorkerLeaseBeforeEgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sup := brokerFixture(t, "tenant-a", "tenant-a")
	if err := sup.Journal.GrantSecret(ctx, "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	sup.RunID = "run_broker_lease"
	if err := sup.Journal.CreateQueuedRun(ctx, sup.RunID, "wf_1", "manual", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	first, err := sup.Journal.ClaimQueuedRuns(ctx, "worker-broker-a", 1, time.Minute)
	if err != nil || len(first) != 1 || first[0].RunID != sup.RunID {
		t.Fatalf("first broker claim = %+v, %v", first, err)
	}
	requests := 0
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})}
	request := wire.ConnectorRequest{CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/"}
	if reply, _ := brokerRequest(t, sup, request); reply.ErrorCode != "denied" || requests != 0 {
		t.Fatalf("local broker bypass of owned run: %+v; requests=%d", reply, requests)
	}
	sup.LeaseOwner = first[0].Owner
	if reply, _ := brokerRequest(t, sup, request); reply.Status != http.StatusOK || requests != 1 {
		t.Fatalf("current worker broker reply: %+v; requests=%d", reply, requests)
	}
	if err := sup.Journal.ExtendLease(ctx, sup.RunID, first[0].Owner, -time.Minute); err != nil {
		t.Fatal(err)
	}
	if reply, _ := brokerRequest(t, sup, request); reply.ErrorCode != "denied" || requests != 1 {
		t.Fatalf("expired worker brokered egress before reap: %+v; requests=%d", reply, requests)
	}
	if n, err := sup.Journal.ReapExpiredLeases(ctx); err != nil || n != 1 {
		t.Fatalf("broker reap = %d, %v", n, err)
	}
	second, err := sup.Journal.ClaimQueuedRuns(ctx, "worker-broker-b", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].RunID != sup.RunID {
		t.Fatalf("replacement broker claim = %+v, %v", second, err)
	}
	if reply, _ := brokerRequest(t, sup, request); reply.ErrorCode != "denied" || requests != 1 {
		t.Fatalf("replaced worker brokered egress: %+v; requests=%d", reply, requests)
	}
	sup.LeaseOwner = second[0].Owner
	if reply, _ := brokerRequest(t, sup, request); reply.Status != http.StatusOK || requests != 2 {
		t.Fatalf("replacement worker broker reply: %+v; requests=%d", reply, requests)
	}
	var expireErr error
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		expireErr = sup.Journal.ExtendLease(ctx, sup.RunID, second[0].Owner, -time.Minute)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"private":"provider-response"}`)), Request: r}, nil
	})}
	if reply, raw := brokerRequest(t, sup, request); expireErr != nil || reply.ErrorCode != "denied" ||
		len(reply.Body) != 0 || bytes.Contains(raw, []byte("provider-response")) || requests != 3 {
		t.Fatalf("lease expired during GET: reply=%+v, expire=%v, requests=%d", reply, expireErr, requests)
	}
}

func TestSalesforceBrokerAdvertisedAndDispatchedOverHostWire(t *testing.T) {
	t.Parallel()
	sup := brokerFixture(t, "tenant-a", "tenant-a")
	if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
		t.Fatal(err)
	}
	sup.connectorHTTPClient = &http.Client{Transport: brokerRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})}
	var incoming, outgoing bytes.Buffer
	request, err := wire.Wrap(7, 0, wire.KindConnectorRequest, wire.ConnectorRequest{
		CredentialID: "oauth:conn_abc", Method: "GET", Path: "/services/data/v62.0/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.NewEncoder(&incoming).Encode(request); err != nil {
		t.Fatal(err)
	}
	disp := &dispatcher{sup: sup, dec: wire.NewDecoder(&incoming), enc: wire.NewEncoder(&outgoing), writeMu: &sync.Mutex{}}
	if err := disp.sendHello(); err != nil {
		t.Fatal(err)
	}
	if err := disp.loop(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("dispatcher loop = %v, want EOF after one request", err)
	}
	decoder := wire.NewDecoder(&outgoing)
	helloFrame, err := decoder.Decode()
	if err != nil || helloFrame.Kind != wire.KindHello {
		t.Fatalf("host hello frame = %+v, %v", helloFrame, err)
	}
	var hello wire.Hello
	if err := wire.Unwrap(helloFrame, &hello); err != nil || !hello.ConnectorBroker {
		t.Fatalf("host did not advertise connector broker: %+v, %v", hello, err)
	}
	replyFrame, err := decoder.Decode()
	if err != nil || replyFrame.Kind != wire.KindConnectorReply || replyFrame.Reply != request.ID {
		t.Fatalf("host broker reply frame = %+v, %v", replyFrame, err)
	}
	var reply wire.ConnectorReply
	if err := wire.Unwrap(replyFrame, &reply); err != nil || reply.Status != http.StatusOK || string(reply.Body) != `{"ok":true}` {
		t.Fatalf("host broker reply = %+v, %v", reply, err)
	}
}

func TestSalesforceRawSecretFetchDeniedAtHostBoundary(t *testing.T) {
	t.Parallel()
	for _, permissive := range []bool{false, true} {
		sup := brokerFixture(t, "tenant-a", "tenant-a")
		sup.ACLPermissive = permissive
		if err := sup.Journal.GrantSecret(context.Background(), "wf_1", "oauth:conn_abc", "admin", ""); err != nil {
			t.Fatal(err)
		}
		secret := fetchSecret(t, sup, "oauth:conn_abc")
		if !secret.NotFound || len(secret.Value) != 0 {
			t.Fatalf("Salesforce raw token released with permissive=%v", permissive)
		}
	}
}

func TestConnectorRetryAfterBounds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{"120", 120 * time.Second}, {"99999999999999999", 24 * time.Hour},
		{"-2", 0}, {"nonsense", 0},
		{now.Add(15 * time.Minute).Format(http.TimeFormat), 15 * time.Minute},
	} {
		if got := connectorRetryAfter(tc.raw, now); got != tc.want {
			t.Errorf("Retry-After %q = %v; want %v", tc.raw, got, tc.want)
		}
	}
}

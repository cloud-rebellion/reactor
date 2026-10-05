package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/internal/safehttp"
)

const (
	maxConnectorPathBytes     = 8192
	maxConnectorResponseBytes = 256 << 10
	maxConnectorRetryAfter    = 24 * time.Hour
)

var errInvalidConnectorPath = errors.New("invalid connector path")

var defaultConnectorHTTPClient = safehttp.Client(false)

// salesforceBrokerPath is deliberately narrower than a general URL parser.
// The child may choose an API path and query, never an origin. Encoded path
// bytes are rejected in this first slice to avoid double-decoding traversal.
func salesforceBrokerPath(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxConnectorPathBytes || !strings.HasPrefix(raw, "/services/data/") ||
		strings.ContainsAny(raw, "#\\") {
		return "", errInvalidConnectorPath
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", errInvalidConnectorPath
		}
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u == nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" ||
		u.Fragment != "" || !strings.HasPrefix(u.Path, "/services/data/") ||
		strings.Contains(u.EscapedPath(), "%") || strings.Contains(u.Path, "\\") {
		return "", errInvalidConnectorPath
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", errInvalidConnectorPath
		}
	}
	return u.RequestURI(), nil
}

// connectorRetryAfter parses only the standard header forms. The value is
// shared account cooldown metadata, never an arbitrary provider instruction
// to sleep a workflow subprocess. Invalid or negative values mean no hint.
func connectorRetryAfter(raw string, now time.Time) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	var delay time.Duration
	if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if secs < 0 {
			return 0
		}
		if secs > int64(maxConnectorRetryAfter/time.Second) {
			return maxConnectorRetryAfter
		}
		delay = time.Duration(secs) * time.Second
	} else if date, err := http.ParseTime(raw); err == nil {
		delay = date.Sub(now)
	} else {
		return 0
	}
	if delay < 0 {
		return 0
	}
	if delay > maxConnectorRetryAfter {
		return maxConnectorRetryAfter
	}
	return delay
}

func (d *dispatcher) sendConnectorReply(requestID int64, reply wire.ConnectorReply) error {
	f, err := wire.Wrap(d.nextID(), requestID, wire.KindConnectorReply, reply)
	if err != nil {
		return err
	}
	return d.write(f)
}

func (d *dispatcher) brokerGrantCurrent(ctx context.Context, workflowID, credentialID string) bool {
	granted, err := d.sup.Journal.HasGrant(ctx, workflowID, credentialID)
	return err == nil && granted
}

// handleConnectorRequest is the host-enforced connector route. It admits
// Salesforce and reviewed generic OAuth GETs. A workflow child cannot choose
// the request origin or receive the OAuth token used by the host transport.
func (d *dispatcher) handleConnectorRequest(ctx context.Context, f wire.Frame) error {
	var body wire.ConnectorRequest
	if err := wire.Unwrap(f, &body); err != nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "invalid_request"})
	}
	if body.Method != http.MethodGet || len(body.CredentialID) > 512 ||
		!strings.HasPrefix(body.CredentialID, "oauth:") || len(body.CredentialID) <= len("oauth:") {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "invalid_request"})
	}
	for _, c := range body.CredentialID {
		if c < 0x20 || c == 0x7f {
			return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "invalid_request"})
		}
	}
	if d.sup.Mode != "live" || d.sup.Journal == nil || d.sup.OAuthTokens == nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	workflowID, tenantID, ok := d.runIdentity(ctx)
	if !ok || tenantID == "" {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	connectionID := strings.TrimPrefix(body.CredentialID, "oauth:")
	ownedTenant, err := d.sup.Journal.SecretTenant(ctx, body.CredentialID)
	if err != nil || ownedTenant != tenantID {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	granted, err := d.sup.Journal.HasGrant(ctx, workflowID, body.CredentialID)
	if err != nil || !granted {
		// Brokered credentials require an explicit grant even when the
		// legacy raw vault ACL is in permissive migration mode.
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	provider, err := d.sup.OAuthTokens.ConnectionProvider(ctx, connectionID, tenantID)
	if err != nil || provider == "" {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	if provider != "salesforce" {
		return d.handleGenericConnectorRequest(ctx, f.ID, body, workflowID, tenantID, connectionID, provider)
	}
	path, err := salesforceBrokerPath(body.Path)
	if err != nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "invalid_request"})
	}
	if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner); err != nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	token, candidateOrigin, accountKey, err := d.sup.OAuthTokens.SalesforceBrokerSession(ctx, connectionID, tenantID)
	if err != nil || token == "" || accountKey == "" {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "connection_unavailable"})
	}
	origin, err := oauth.ValidateSalesforceAPIOrigin(candidateOrigin)
	if err != nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "connection_unavailable"})
	}
	if err := d.sup.Journal.AppendRuntimeSecretAccess(ctx, d.sup.LeaseOwner, journal.RuntimeSecretAccess{
		TenantID: tenantID, WorkflowID: workflowID, RunID: d.sup.RunID,
		SecretRef: body.CredentialID, SecretKind: "oauth",
	}); err != nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "audit_unavailable"})
	}

	policy := journal.ProviderPermitPolicy{RequestsPerMinute: 30, MaxConcurrent: 2}
	permit, err := d.sup.Journal.AcquireProviderPermit(ctx, tenantID, connectionID, policy)
	if err != nil {
		var denied *journal.ProviderPermitDeniedError
		if errors.As(err, &denied) {
			return d.sendConnectorReply(f.ID, wire.ConnectorReply{
				ErrorCode: "rate_limited", RetryAfterMs: denied.RetryAfter.Milliseconds(),
			})
		}
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
	}
	sharedPermit, err := d.sup.Journal.AcquireSharedProviderPermit(ctx, tenantID, connectionID,
		"salesforce", accountKey, policy)
	if err != nil {
		// A shared-account denial must not leave a connection lease active.
		// The per-connection rolling receipt remains charged conservatively.
		completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if releaseErr := d.sup.Journal.CompleteProviderPermit(completeCtx, permit, 0); releaseErr != nil {
			return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
		}
		var denied *journal.ProviderPermitDeniedError
		if errors.As(err, &denied) {
			return d.sendConnectorReply(f.ID, wire.ConnectorReply{
				ErrorCode: "rate_limited", RetryAfterMs: denied.RetryAfter.Milliseconds(),
			})
		}
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
	}

	// A permit can wait behind contention while this worker loses its lease.
	// Recheck immediately before the token is used for outbound HTTP. Keep
	// both permits in the release path even when this check denies the call.
	reply := wire.ConnectorReply{ErrorCode: "denied"}
	var retryAfter time.Duration
	current, currentErr := d.sup.OAuthTokens.SalesforceBrokerSessionCurrent(ctx, connectionID, tenantID, token, origin, accountKey)
	if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner); err == nil &&
		d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) && currentErr == nil && current {
		reply, retryAfter = d.brokerGET(ctx, origin, path, token)
	}
	// A cancelled run must still release both provider leases. Failure to
	// persist either completion suppresses even a successful GET response.
	completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	sharedErr := d.sup.Journal.CompleteSharedProviderPermit(completeCtx, sharedPermit, retryAfter)
	connectionErr := d.sup.Journal.CompleteProviderPermit(completeCtx, permit, retryAfter)
	if sharedErr != nil || connectionErr != nil {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
	}
	// A lease can also be reaped during a slow provider response. Never hand
	// that response to a stale child even though the already-sent GET cannot
	// be rolled back by this final read.
	current, currentErr = d.sup.OAuthTokens.SalesforceBrokerSessionCurrent(ctx, connectionID, tenantID, token, origin, accountKey)
	if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner); err != nil ||
		!d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) || currentErr != nil || !current {
		return d.sendConnectorReply(f.ID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	return d.sendConnectorReply(f.ID, reply)
}

// handleGenericConnectorRequest extends the host-owned transport to an
// operator-reviewed connection. Existing legacy-raw connections have no
// policy and cannot enter this route. The tenant/provider shared permit is
// deliberately conservative: it groups all of a tenant's connections to one
// provider because generic OAuth responses do not prove account identity.
func (d *dispatcher) handleGenericConnectorRequest(ctx context.Context, requestID int64, body wire.ConnectorRequest, workflowID, tenantID, connectionID, providerID string) error {
	if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner); err != nil {
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	session, err := d.sup.OAuthTokens.GenericBrokerSession(ctx, tenantID, connectionID)
	if err != nil || session.ProviderID != providerID || session.BearerToken() == "" || session.Version < 1 || session.Method != http.MethodGet {
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "connection_unavailable"})
	}
	path, err := oauth.ValidateBrokerPath(body.Path, session.PathPrefix)
	if err != nil {
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "invalid_request"})
	}
	if err := d.sup.Journal.AppendRuntimeSecretAccess(ctx, d.sup.LeaseOwner, journal.RuntimeSecretAccess{
		TenantID: tenantID, WorkflowID: workflowID, RunID: d.sup.RunID,
		SecretRef: body.CredentialID, SecretKind: "oauth", PolicyRevision: session.Version,
	}); err != nil {
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "audit_unavailable"})
	}
	policy := journal.ProviderPermitPolicy{RequestsPerMinute: 30, MaxConcurrent: 2}
	permit, err := d.sup.Journal.AcquireProviderPermit(ctx, tenantID, connectionID, policy)
	if err != nil {
		var denied *journal.ProviderPermitDeniedError
		if errors.As(err, &denied) {
			return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "rate_limited", RetryAfterMs: denied.RetryAfter.Milliseconds()})
		}
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
	}
	sum := sha256.Sum256([]byte("reactor-generic-provider-budget-v1\x00" + tenantID + "\x00" + providerID))
	accountKey := hex.EncodeToString(sum[:])
	sharedPermit, err := d.sup.Journal.AcquireSharedProviderPermit(ctx, tenantID, connectionID, providerID, accountKey, policy)
	if err != nil {
		completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if releaseErr := d.sup.Journal.CompleteProviderPermit(completeCtx, permit, 0); releaseErr != nil {
			return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
		}
		var denied *journal.ProviderPermitDeniedError
		if errors.As(err, &denied) {
			return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "rate_limited", RetryAfterMs: denied.RetryAfter.Milliseconds()})
		}
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
	}
	reply := wire.ConnectorReply{ErrorCode: "denied"}
	var retryAfter time.Duration
	current, currentErr := d.sup.OAuthTokens.BrokerPolicyCurrent(ctx, session)
	if currentErr == nil && current && d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner) == nil &&
		d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) {
		reply, retryAfter = d.brokerGET(ctx, session.APIOrigin, path, session.BearerToken())
	}
	completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	sharedErr := d.sup.Journal.CompleteSharedProviderPermit(completeCtx, sharedPermit, retryAfter)
	connectionErr := d.sup.Journal.CompleteProviderPermit(completeCtx, permit, retryAfter)
	if sharedErr != nil || connectionErr != nil {
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "permit_unavailable"})
	}
	current, currentErr = d.sup.OAuthTokens.BrokerPolicyCurrent(ctx, session)
	if currentErr != nil || !current || d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner) != nil ||
		!d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) {
		return d.sendConnectorReply(requestID, wire.ConnectorReply{ErrorCode: "denied"})
	}
	return d.sendConnectorReply(requestID, reply)
}

func (d *dispatcher) brokerGET(ctx context.Context, origin, apiPath, token string) (wire.ConnectorReply, time.Duration) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+apiPath, nil)
	if err != nil {
		return wire.ConnectorReply{ErrorCode: "invalid_request"}, 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	client := *defaultConnectorHTTPClient
	if d.sup.connectorHTTPClient != nil {
		client = *d.sup.connectorHTTPClient
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		// net/http errors can embed the full request URL and query. Neither
		// that text nor any provider body is sent over the wire or logged.
		return wire.ConnectorReply{ErrorCode: "upstream_unavailable"}, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var after time.Duration
		if resp.StatusCode == http.StatusTooManyRequests {
			after = connectorRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		}
		return wire.ConnectorReply{
			Status: resp.StatusCode, ErrorCode: "upstream_status", RetryAfterMs: after.Milliseconds(),
		}, after
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxConnectorResponseBytes+1))
	if err != nil {
		return wire.ConnectorReply{Status: resp.StatusCode, ErrorCode: "upstream_read_error"}, 0
	}
	if len(raw) > maxConnectorResponseBytes {
		return wire.ConnectorReply{Status: resp.StatusCode, ErrorCode: "response_too_large"}, 0
	}
	return wire.ConnectorReply{Status: resp.StatusCode, Body: raw}, 0
}

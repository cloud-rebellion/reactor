package oauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
)

// MailBrokerSession is a host-only, current token snapshot for the fixed
// Google/Microsoft send endpoints. Its formatters deliberately omit the token.
type MailBrokerSession struct {
	ConnectionID string
	TenantID     string
	ProviderID   string
	token        string
	cipherHash   [sha256.Size]byte
}

func (s MailBrokerSession) BearerToken() string { return s.token }
func (s MailBrokerSession) String() string {
	return fmt.Sprintf("oauth.MailBrokerSession{connection:%q provider:%q token:[REDACTED]}", s.ConnectionID, s.ProviderID)
}
func (s MailBrokerSession) GoString() string { return s.String() }

var ErrMailBrokerUnavailable = errors.New("oauth: mail broker connection unavailable")

type mailSnapshot struct {
	providerID, name, authURL, tokenURL, requestedScopes, grantedScopes string
	status, accessMode, legacyReason                                    string
	enabled                                                             bool
	encrypted                                                           []byte
}

func (s *Store) mailSnapshot(ctx context.Context, tenantID, connectionID string) (mailSnapshot, error) {
	if tenantID == "" || connectionID == "" {
		return mailSnapshot{}, ErrMailBrokerUnavailable
	}
	const query = `SELECT c.provider_id, c.name, c.token_encrypted, c.status,
		c.token_access_mode, c.legacy_raw_reason, c.scopes, p.auth_url,
		p.token_url, p.scopes, p.enabled
		FROM oauth_connections c JOIN oauth_providers p ON p.provider_id=c.provider_id
		WHERE c.id=$1 AND c.tenant_id=$2`
	var row mailSnapshot
	var enabled any
	err := s.db.QueryRowContext(ctx, s.bind(query), connectionID, tenantID).Scan(
		&row.providerID, &row.name, &row.encrypted, &row.status,
		&row.accessMode, &row.legacyReason, &row.grantedScopes, &row.authURL,
		&row.tokenURL, &row.requestedScopes, &enabled,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return mailSnapshot{}, ErrMailBrokerUnavailable
		}
		return mailSnapshot{}, wrap("mail broker connection", err)
	}
	row.enabled = parseBool(enabled)
	if !row.allowed() {
		return mailSnapshot{}, ErrMailBrokerUnavailable
	}
	return row, nil
}

func (r mailSnapshot) allowed() bool {
	return r.status == "connected" && r.enabled &&
		(r.accessMode == "broker_only" || r.accessMode == "legacy_raw" && r.legacyReason == "email_adapter") &&
		legacyEmailRawException(r.providerID, r.authURL, r.tokenURL) &&
		legacyEmailScopesAllowed(r.providerID, r.requestedScopes, r.grantedScopes)
}

// MailBrokerSession obtains a fresh token only after verifying the current
// tenant, canonical OAuth endpoints, send-only scopes, and access mode.
func (s *Store) MailBrokerSession(ctx context.Context, tenantID, connectionID string) (MailBrokerSession, error) {
	if _, err := s.mailSnapshot(ctx, tenantID, connectionID); err != nil {
		return MailBrokerSession{}, err
	}
	if _, err := s.Token(ctx, connectionID, tenantID); err != nil {
		return MailBrokerSession{}, err
	}
	row, err := s.mailSnapshot(ctx, tenantID, connectionID)
	if err != nil {
		return MailBrokerSession{}, err
	}
	blob, err := s.loadTokenBlob(row.encrypted, connectionTokenIdentity(tenantID, row.providerID, row.name))
	if err != nil || blob.AccessToken == "" || !legacyEmailScopesAllowed(row.providerID, row.requestedScopes, blob.Scope) {
		return MailBrokerSession{}, ErrMailBrokerUnavailable
	}
	return MailBrokerSession{
		ConnectionID: connectionID, TenantID: tenantID, ProviderID: row.providerID,
		token: blob.AccessToken, cipherHash: sha256.Sum256(row.encrypted),
	}, nil
}

// MailBrokerSessionCurrent catches endpoint edits, scope expansion, token
// reconnects, and connection revocation before egress and response release.
func (s *Store) MailBrokerSessionCurrent(ctx context.Context, session MailBrokerSession) (bool, error) {
	row, err := s.mailSnapshot(ctx, session.TenantID, session.ConnectionID)
	if errors.Is(err, ErrMailBrokerUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.providerID == session.ProviderID && sha256.Sum256(row.encrypted) == session.cipherHash, nil
}

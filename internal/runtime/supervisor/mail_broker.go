package supervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/wire"
	"github.com/bright-interaction/reactor/sdk/email"
)

const (
	maxMailRequestBytes  = 256 << 10
	maxMailResponseBytes = 8 << 10
	googleSendURL        = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
	microsoftSendURL     = "https://graph.microsoft.com/v1.0/me/sendMail"
)

type mailTokenResolver interface {
	MailBrokerSession(ctx context.Context, tenantID, connectionID string) (oauth.MailBrokerSession, error)
	MailBrokerSessionCurrent(ctx context.Context, session oauth.MailBrokerSession) (bool, error)
}

func (d *dispatcher) sendMailReply(requestID int64, reply wire.MailSendReply) error {
	f, err := wire.Wrap(d.nextID(), requestID, wire.KindMailSendReply, reply)
	if err != nil {
		return err
	}
	return d.write(f)
}

// handleMailSendRequest is the only connected-mail mutation route. The child
// cannot choose a URL, method, header, or token. Old hosts never advertise
// MailBroker, so a new SDK refuses before sending this frame to one.
func (d *dispatcher) handleMailSendRequest(ctx context.Context, f wire.Frame) error {
	if len(f.Body) == 0 || len(f.Body) > maxMailRequestBytes {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "invalid_request"})
	}
	var body wire.MailSendRequest
	if err := wire.Unwrap(f, &body); err != nil {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "invalid_request"})
	}
	if !strings.HasPrefix(body.CredentialID, "oauth:") || len(body.CredentialID) <= len("oauth:") ||
		len(body.CredentialID) > 256 || strings.IndexFunc(body.CredentialID, func(r rune) bool {
		return r < 0x21 || r == 0x7f
	}) >= 0 {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "invalid_request"})
	}
	if body.StepName == "" || body.StepSeq < 1 || body.StepAttempt < 1 || body.IdempotencyKey == "" ||
		len(body.StepName) > 256 || len(body.IdempotencyKey) > 512 {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "invalid_request"})
	}
	if d.sup.Mode != "live" || d.sup.Journal == nil || d.sup.OAuthTokens == nil {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "denied"})
	}
	resolver, ok := d.sup.OAuthTokens.(mailTokenResolver)
	if !ok {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "connection_unavailable"})
	}
	message := email.Message{
		From: body.Message.From, To: body.Message.To, Cc: body.Message.Cc,
		Subject: body.Message.Subject, Text: body.Message.Text, HTML: body.Message.HTML,
	}
	if err := message.Validate(); err != nil {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "invalid_request"})
	}
	workflowID, tenantID, identityOK := d.runIdentity(ctx)
	if !identityOK || tenantID == "" {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "denied"})
	}
	ownedTenant, err := d.sup.Journal.SecretTenant(ctx, body.CredentialID)
	if err != nil || ownedTenant != tenantID || !d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "denied"})
	}
	if err := d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner); err != nil {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "denied"})
	}
	connectionID := strings.TrimPrefix(body.CredentialID, "oauth:")
	session, err := resolver.MailBrokerSession(ctx, tenantID, connectionID)
	if err != nil || session.TenantID != tenantID || session.ConnectionID != connectionID || session.BearerToken() == "" {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "connection_unavailable"})
	}
	endpoint, payload, err := mailRequestPayload(session.ProviderID, message)
	if err != nil {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "invalid_request"})
	}
	if err := d.sup.Journal.AppendRuntimeSecretAccess(ctx, d.sup.LeaseOwner, journal.RuntimeSecretAccess{
		TenantID: tenantID, WorkflowID: workflowID, RunID: d.sup.RunID,
		SecretRef: body.CredentialID, SecretKind: "oauth",
	}); err != nil {
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "audit_unavailable"})
	}
	policy := journal.ProviderPermitPolicy{RequestsPerMinute: 30, MaxConcurrent: 2}
	permit, err := d.sup.Journal.AcquireProviderPermit(ctx, tenantID, connectionID, policy)
	if err != nil {
		return d.sendMailReply(f.ID, mailPermitError(err))
	}
	sum := sha256.Sum256([]byte("reactor-mail-provider-budget-v1\x00" + tenantID + "\x00" + session.ProviderID))
	sharedPermit, err := d.sup.Journal.AcquireSharedProviderPermit(ctx, tenantID, connectionID,
		session.ProviderID, hex.EncodeToString(sum[:]), policy)
	if err != nil {
		completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if d.sup.Journal.CompleteProviderPermit(completeCtx, permit, 0) != nil {
			return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "permit_unavailable"})
		}
		return d.sendMailReply(f.ID, mailPermitError(err))
	}
	reply := wire.MailSendReply{ErrorCode: "denied"}
	var retryAfter time.Duration
	intentAdmitted := false
	current, currentErr := resolver.MailBrokerSessionCurrent(ctx, session)
	if currentErr == nil && current && d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) &&
		d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner) == nil {
		// The digest binds the once-only Step intent to the exact account,
		// provider endpoint, and canonical bytes that will be sent. Persist the
		// intent before POST; a crash or timeout cannot silently send again.
		h := sha256.New()
		_, _ = h.Write([]byte("reactor-mail-send-v1\x00" + body.CredentialID + "\x00" + session.ProviderID + "\x00" + endpoint + "\x00"))
		_, _ = h.Write(payload)
		admission, admitErr := d.sup.Journal.AdmitMailSend(ctx, d.sup.RunID, d.sup.LeaseOwner,
			body.StepName, body.StepSeq, body.StepAttempt, body.IdempotencyKey, hex.EncodeToString(h.Sum(nil)),
			journal.MailSendTarget{ProviderID: session.ProviderID, ConnectionID: connectionID})
		if admitErr != nil {
			reply = wire.MailSendReply{ErrorCode: "intent_unavailable"}
		} else {
			intentAdmitted = true
			switch admission.Disposition {
			case journal.MailSendDispositionConfirmed:
				if admission.ProviderID != session.ProviderID {
					reply = wire.MailSendReply{ErrorCode: "ambiguous"}
				} else {
					status := http.StatusOK
					if session.ProviderID == "microsoft" {
						status = http.StatusAccepted
					}
					reply = wire.MailSendReply{Status: status, MessageID: admission.MessageID}
				}
			case journal.MailSendDispositionAmbiguous:
				reply = wire.MailSendReply{ErrorCode: "ambiguous"}
			case journal.MailSendDispositionSend:
				// Admission is the final authorization gate. Even if the HTTP
				// outcome is lost, this Step can never issue a second POST.
				reply, retryAfter = d.brokerMailPOST(ctx, endpoint, payload, session.BearerToken(), session.ProviderID)
				if reply.ErrorCode != "" {
					reply.ErrorCode = "ambiguous"
				} else {
					confirmCtx, confirmCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					confirmErr := d.sup.Journal.ConfirmMailSend(confirmCtx, admission.IntentID, session.ProviderID, reply.MessageID)
					confirmCancel()
					if confirmErr != nil {
						reply = wire.MailSendReply{ErrorCode: "ambiguous"}
					}
				}
			default:
				reply = wire.MailSendReply{ErrorCode: "ambiguous"}
			}
		}
	}
	completeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	sharedErr := d.sup.Journal.CompleteSharedProviderPermit(completeCtx, sharedPermit, retryAfter)
	connectionErr := d.sup.Journal.CompleteProviderPermit(completeCtx, permit, retryAfter)
	if sharedErr != nil || connectionErr != nil {
		if intentAdmitted {
			return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "ambiguous"})
		}
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "permit_unavailable"})
	}
	current, currentErr = resolver.MailBrokerSessionCurrent(ctx, session)
	if currentErr != nil || !current || !d.brokerGrantCurrent(ctx, workflowID, body.CredentialID) ||
		d.sup.Journal.VerifyRuntimeSecretRun(ctx, d.sup.RunID, workflowID, tenantID, d.sup.LeaseOwner) != nil {
		if intentAdmitted {
			return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "ambiguous"})
		}
		return d.sendMailReply(f.ID, wire.MailSendReply{ErrorCode: "denied"})
	}
	return d.sendMailReply(f.ID, reply)
}

func mailPermitError(err error) wire.MailSendReply {
	var denied *journal.ProviderPermitDeniedError
	if errors.As(err, &denied) {
		return wire.MailSendReply{ErrorCode: "rate_limited", Status: http.StatusTooManyRequests}
	}
	return wire.MailSendReply{ErrorCode: "permit_unavailable"}
}

func mailRequestPayload(providerID string, message email.Message) (string, []byte, error) {
	var endpoint string
	var data any
	switch providerID {
	case "google":
		raw, err := message.GmailPayload()
		if err != nil {
			return "", nil, err
		}
		endpoint = googleSendURL
		data = map[string]string{"raw": base64.URLEncoding.EncodeToString(raw)}
	case "microsoft":
		body, err := message.OutlookPayload()
		if err != nil {
			return "", nil, err
		}
		endpoint = microsoftSendURL
		data = body
	default:
		return "", nil, errors.New("unsupported mail provider")
	}
	payload, err := json.Marshal(data)
	if err != nil || len(payload) > maxMailRequestBytes {
		return "", nil, errors.New("mail request exceeds limit")
	}
	return endpoint, payload, nil
}

func (d *dispatcher) brokerMailPOST(ctx context.Context, endpoint string, payload []byte, token, providerID string) (wire.MailSendReply, time.Duration) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return wire.MailSendReply{ErrorCode: "invalid_request"}, 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := *defaultConnectorHTTPClient
	if d.sup.connectorHTTPClient != nil {
		client = *d.sup.connectorHTTPClient
	}
	if client.Timeout <= 0 || client.Timeout > 15*time.Second {
		client.Timeout = 15 * time.Second
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	// One call only: a Step key cannot prove whether an ambiguous provider
	// POST succeeded, so the host must never retry it automatically.
	resp, err := client.Do(req)
	if err != nil {
		return wire.MailSendReply{ErrorCode: "upstream_unavailable"}, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 ||
		(providerID == "microsoft" && resp.StatusCode != http.StatusAccepted) {
		var after time.Duration
		if resp.StatusCode == http.StatusTooManyRequests {
			after = connectorRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		}
		return wire.MailSendReply{Status: resp.StatusCode, ErrorCode: "upstream_status"}, after
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMailResponseBytes+1))
	if err != nil || len(raw) > maxMailResponseBytes {
		return wire.MailSendReply{Status: resp.StatusCode, ErrorCode: "upstream_read_error"}, 0
	}
	if providerID == "microsoft" {
		return wire.MailSendReply{Status: resp.StatusCode}, 0
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &result) != nil || result.ID == "" || len(result.ID) > 256 ||
		strings.IndexFunc(result.ID, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
		}) >= 0 {
		return wire.MailSendReply{Status: resp.StatusCode, ErrorCode: "upstream_read_error"}, 0
	}
	return wire.MailSendReply{Status: resp.StatusCode, MessageID: result.ID}, 0
}

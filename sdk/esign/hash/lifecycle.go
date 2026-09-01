package hash

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/sdk/esign"
	"github.com/bright-interaction/reactor/sdk/esign/internal/strictjson"
)

const maxWebhookEventBytes = 1 << 20

const (
	KindDocumentSent             = "document.sent"
	KindDocumentOpened           = "document.opened"
	KindDocumentViewed           = "document.viewed"
	KindDocumentFieldFilled      = "document.field_filled"
	KindDocumentSigned           = "document.signed"
	KindDocumentCompleted        = "document.completed"
	KindDocumentDeclined         = "document.declined"
	KindDocumentChangesRequested = "document.changes_requested"
	KindDocumentVoided           = "document.voided"
	KindDocumentExpired          = "document.expired"
)

// ErrUncorrelatedDocument identifies a valid event from a manual/non-automation
// Hash document. A tenant-level Hash endpoint receives those alongside
// automation documents; lifecycle workflows should acknowledge and ignore the
// event without calling the CRM.
var ErrUncorrelatedDocument = errors.New("hash lifecycle: document is not automation-correlated")

type webhookReference struct {
	ID string `json:"id"`
}

type webhookEnvelope struct {
	EventID             string                     `json:"event_id"`
	Kind                string                     `json:"kind"`
	OccurredAt          time.Time                  `json:"occurred_at"`
	OrgID               string                     `json:"org_id"`
	AutomationRequestID json.RawMessage            `json:"automation_request_id,omitempty"`
	Document            *webhookReference          `json:"document"`
	Recipient           *webhookReference          `json:"recipient,omitempty"`
	Payload             map[string]json.RawMessage `json:"payload,omitempty"`
}

type webhookProjection struct {
	EventID             string            `json:"event_id"`
	Kind                string            `json:"kind"`
	OccurredAt          time.Time         `json:"occurred_at"`
	OrgID               string            `json:"org_id"`
	AutomationRequestID json.RawMessage   `json:"automation_request_id,omitempty"`
	Document            *webhookReference `json:"document"`
}

// IsLifecycleKind reports whether a public Hash document event is useful to a
// CRM lifecycle projection. Recipient and internal audit events are excluded.
func IsLifecycleKind(kind string) bool {
	switch kind {
	case KindDocumentSent,
		KindDocumentOpened,
		KindDocumentViewed,
		KindDocumentFieldFilled,
		KindDocumentSigned,
		KindDocumentCompleted,
		KindDocumentDeclined,
		KindDocumentChangesRequested,
		KindDocumentVoided,
		KindDocumentExpired:
		return true
	default:
		return false
	}
}

// ProjectWebhookEvent removes Hash payload and recipient data immediately
// after hash-v1 authentication and before Reactor persists a run input. It
// retains only fields a lifecycle workflow needs for tenant binding,
// correlation, filtering, and CRM writeback. The original signed bytes must
// still be used for webhook-delivery deduplication and conflict detection.
func ProjectWebhookEvent(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxWebhookEventBytes {
		return nil, errors.New("hash lifecycle: event body is empty or exceeds 1 MiB")
	}
	var envelope webhookEnvelope
	if err := strictjson.Decode(raw, &envelope); err != nil {
		return nil, errors.New("hash lifecycle: invalid event envelope")
	}
	projected, err := json.Marshal(webhookProjection{
		EventID:             envelope.EventID,
		Kind:                envelope.Kind,
		OccurredAt:          envelope.OccurredAt,
		OrgID:               envelope.OrgID,
		AutomationRequestID: envelope.AutomationRequestID,
		Document:            envelope.Document,
	})
	if err != nil {
		return nil, errors.New("hash lifecycle: project event envelope")
	}
	return projected, nil
}

// DecodeLifecycleEvent strictly validates an authenticated Hash webhook body,
// binds it to one operator-configured Hash organization, and returns only the
// five non-PII fields permitted at the CRM boundary. The recipient object and
// provider payload are parsed for envelope correctness and then discarded.
// Signature verification remains the hash-v1 trigger's responsibility.
func DecodeLifecycleEvent(raw []byte, trustedOrgID string) (esign.LifecycleEvent, error) {
	var result esign.LifecycleEvent
	if err := validateBoundIdentifier(trustedOrgID); err != nil {
		return result, errors.New("hash lifecycle: trusted organization ID is not configured correctly")
	}
	if len(raw) == 0 || len(raw) > maxWebhookEventBytes {
		return result, errors.New("hash lifecycle: event body is empty or exceeds 1 MiB")
	}

	var envelope webhookEnvelope
	if err := strictjson.Decode(raw, &envelope); err != nil {
		// Parser details can contain an attacker-controlled unknown member name.
		// Keep the workflow error fixed so payload data cannot enter logs.
		return result, errors.New("hash lifecycle: invalid event envelope")
	}
	if envelope.OrgID != trustedOrgID {
		return result, errors.New("hash lifecycle: event organization is not trusted")
	}
	if !IsLifecycleKind(envelope.Kind) {
		return result, errors.New("hash lifecycle: unsupported event kind")
	}
	if envelope.Document == nil {
		return result, errors.New("hash lifecycle: document is required")
	}

	result = esign.LifecycleEvent{
		EventID:    envelope.EventID,
		Kind:       envelope.Kind,
		OccurredAt: envelope.OccurredAt,
		DocumentID: envelope.Document.ID,
	}
	// Validate all required non-correlation fields before treating an absent
	// automation_request_id as a deliberate manual-document filter.
	validationProbe := result
	validationProbe.AutomationRequestID = "uncorrelated"
	if err := validationProbe.Validate(); err != nil {
		return esign.LifecycleEvent{}, errors.New("hash lifecycle: required correlation field is invalid")
	}
	if len(envelope.AutomationRequestID) == 0 {
		return esign.LifecycleEvent{}, ErrUncorrelatedDocument
	}
	if err := strictjson.Decode(envelope.AutomationRequestID, &result.AutomationRequestID); err != nil {
		return esign.LifecycleEvent{}, errors.New("hash lifecycle: automation request correlation is invalid")
	}
	if err := result.Validate(); err != nil {
		return esign.LifecycleEvent{}, errors.New("hash lifecycle: required correlation field is invalid")
	}
	return result, nil
}

func validateBoundIdentifier(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 200 || !utf8.ValidString(value) {
		return errors.New("invalid identifier")
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return errors.New("invalid identifier")
		}
	}
	return nil
}

package esign

import (
	"errors"
	"time"
)

// LifecycleEvent is the minimal provider-neutral document state change that
// may cross from an e-signature provider into a CRM. It deliberately has no
// organization, recipient, or provider payload fields: adapters must validate
// those at ingress and discard them before constructing this value.
type LifecycleEvent struct {
	EventID             string    `json:"event_id"`
	Kind                string    `json:"kind"`
	OccurredAt          time.Time `json:"occurred_at"`
	AutomationRequestID string    `json:"automation_request_id"`
	DocumentID          string    `json:"document_id"`
}

// Validate enforces the provider-neutral forwarding contract. Provider
// adapters remain responsible for their own event-kind allowlist and tenant
// binding before a LifecycleEvent is created.
func (e LifecycleEvent) Validate() error {
	if err := validateIdentifier("lifecycle.event_id", e.EventID); err != nil {
		return err
	}
	if err := validateIdentifier("lifecycle.kind", e.Kind); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() {
		return errors.New("esign: lifecycle.occurred_at is required")
	}
	if err := validateIdentifier("lifecycle.automation_request_id", e.AutomationRequestID); err != nil {
		return err
	}
	if err := validateIdentifier("lifecycle.document_id", e.DocumentID); err != nil {
		return err
	}
	return nil
}

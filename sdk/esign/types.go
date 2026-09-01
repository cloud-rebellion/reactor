// Package esign defines the provider-neutral request event consumed by
// e-signature workflows. Provider adapters live in subpackages.
package esign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/reactor/sdk/esign/internal/strictjson"
)

var (
	recipientRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	variableNamePattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
	rfc3339Pattern       = regexp.MustCompile(`^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)
)

const (
	// SpecVersion is the current inbound event schema version.
	SpecVersion = "1.0"
	// EventTypeDocumentRequested identifies a request to create and send one
	// document from an operator-configured template profile.
	EventTypeDocumentRequested = "esignature.document.requested.v1"
	// MinimumExpiryLead is a replay-stable producer guard measured from the
	// immutable event time. It leaves a modest transport margin beyond Hash's
	// strict five-minute-at-admission requirement, but queue delay can consume it.
	MinimumExpiryLead = 10 * time.Minute

	maxEventBytes     = 1 << 20
	maxRecipients     = 50
	maxVariables      = 200
	maxVariableValue  = 16 << 10
	maxIdentifierSize = 200
	maxNameRunes      = 200
	maxEmailBytes     = 254
)

// DocumentRequested is the canonical webhook body accepted from a CRM,
// Google Apps Script, or any other HMAC-capable producer.
type DocumentRequested struct {
	SpecVersion string    `json:"spec_version"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	OccurredAt  time.Time `json:"occurred_at"`
	Source      Source    `json:"source"`
	Customer    Customer  `json:"customer"`
	Document    Document  `json:"document"`
}

// Source identifies the producing system. It is correlation data only; it
// must never select the Hash organization, API key, or base URL.
type Source struct {
	Provider         string `json:"provider"`
	TenantExternalID string `json:"tenant_external_id,omitempty"`
}

// Customer contains the normalized customer identity used by the document.
type Customer struct {
	ExternalID  string `json:"external_id"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	CompanyName string `json:"company_name,omitempty"`
	Phone       string `json:"phone,omitempty"`
	Locale      string `json:"locale,omitempty"`
}

// Document selects an operator-owned template profile and supplies only data
// to merge into it. TemplateKey is not a Hash template UUID.
type Document struct {
	TemplateKey string            `json:"template_key"`
	Name        string            `json:"name,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
	Recipients  []Recipient       `json:"recipients"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// Recipient is a provider-neutral participant in the signing ceremony.
type Recipient struct {
	ExternalID   string `json:"external_id,omitempty"`
	Role         string `json:"role"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Locale       string `json:"locale,omitempty"`
	SigningOrder int32  `json:"signing_order"`
}

// DecodeDocumentRequested strictly decodes and validates one canonical event.
// Unknown fields and trailing JSON are rejected so a producer cannot believe a
// misspelled security- or routing-related field was honored.
func DecodeDocumentRequested(raw []byte) (DocumentRequested, error) {
	var event DocumentRequested
	if len(raw) == 0 {
		return event, errors.New("esign: empty event")
	}
	if len(raw) > maxEventBytes {
		return event, errors.New("esign: event exceeds 1 MiB")
	}
	if err := strictjson.Decode(raw, &event); err != nil {
		return DocumentRequested{}, fmt.Errorf("esign: decode event: %w", err)
	}
	if err := validateVariableJSONTypes(raw); err != nil {
		return DocumentRequested{}, err
	}
	if err := validateTimestampJSONSyntax(raw); err != nil {
		return DocumentRequested{}, err
	}
	if err := event.Validate(); err != nil {
		return DocumentRequested{}, err
	}
	return event, nil
}

func validateTimestampJSONSyntax(raw []byte) error {
	var envelope struct {
		OccurredAt json.RawMessage `json:"occurred_at"`
		Document   json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errors.New("esign: timestamps must use strict RFC3339 syntax")
	}
	if err := validateRFC3339JSONValue(envelope.OccurredAt, true); err != nil {
		return fmt.Errorf("esign: occurred_at %w", err)
	}
	if len(envelope.Document) == 0 {
		return nil
	}
	var document struct {
		ExpiresAt json.RawMessage `json:"expires_at"`
	}
	if err := json.Unmarshal(envelope.Document, &document); err != nil {
		return errors.New("esign: timestamps must use strict RFC3339 syntax")
	}
	if err := validateRFC3339JSONValue(document.ExpiresAt, false); err != nil {
		return fmt.Errorf("esign: document.expires_at %w", err)
	}
	return nil
}

func validateRFC3339JSONValue(raw json.RawMessage, required bool) error {
	if len(raw) == 0 {
		if required {
			return errors.New("is required")
		}
		return nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '"' {
		return errors.New("must use strict RFC3339 syntax")
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil || !rfc3339Pattern.MatchString(value) {
		return errors.New("must use strict RFC3339 syntax")
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return errors.New("must use strict RFC3339 syntax")
	}
	return nil
}

// encoding/json treats null as the zero value when decoding into a string.
// Inspect the signed source bytes so the advertised string-only variables
// contract cannot silently turn an explicit JSON null into contractual text.
func validateVariableJSONTypes(raw []byte) error {
	var envelope struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errors.New("esign: document.variables must be an object of string values")
	}
	var document struct {
		Variables json.RawMessage `json:"variables"`
	}
	if len(envelope.Document) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Document, &document); err != nil {
		return errors.New("esign: document.variables must be an object of string values")
	}
	if len(document.Variables) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(document.Variables)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("esign: document.variables must be an object of string values")
	}
	var variables map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &variables); err != nil || variables == nil {
		return errors.New("esign: document.variables must be an object of string values")
	}
	for _, encoded := range variables {
		value := bytes.TrimSpace(encoded)
		if len(value) == 0 || value[0] != '"' {
			return errors.New("esign: document.variables values must be strings")
		}
		var decoded string
		if err := json.Unmarshal(value, &decoded); err != nil {
			return errors.New("esign: document.variables values must be strings")
		}
	}
	return nil
}

// Validate enforces the stable, provider-neutral event contract. It does not
// make authorization decisions: tenant, Hash organization, endpoint, and
// template UUID must all come from trusted Reactor configuration.
func (e DocumentRequested) Validate() error {
	if e.SpecVersion != SpecVersion {
		return fmt.Errorf("esign: unsupported spec_version %q", e.SpecVersion)
	}
	if e.EventType != EventTypeDocumentRequested {
		return fmt.Errorf("esign: unsupported event_type %q", e.EventType)
	}
	if err := validateIdentifier("event_id", e.EventID); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() {
		return errors.New("esign: occurred_at is required")
	}
	if err := validateIdentifier("source.provider", e.Source.Provider); err != nil {
		return err
	}
	if e.Source.TenantExternalID != "" {
		if err := validateIdentifier("source.tenant_external_id", e.Source.TenantExternalID); err != nil {
			return err
		}
	}
	if err := validateIdentifier("customer.external_id", e.Customer.ExternalID); err != nil {
		return err
	}
	if err := validateName("customer.name", e.Customer.Name); err != nil {
		return err
	}
	if err := validateEmail("customer.email", e.Customer.Email); err != nil {
		return err
	}
	if err := validateText("customer.company_name", e.Customer.CompanyName, 300, false); err != nil {
		return err
	}
	if err := validateText("customer.phone", e.Customer.Phone, 64, false); err != nil {
		return err
	}
	if err := validateText("customer.locale", e.Customer.Locale, 35, false); err != nil {
		return err
	}
	if err := validateIdentifier("document.template_key", e.Document.TemplateKey); err != nil {
		return err
	}
	if err := validateText("document.name", e.Document.Name, 300, true); err != nil {
		return err
	}
	if len(e.Document.Variables) > maxVariables {
		return fmt.Errorf("esign: document.variables has more than %d entries", maxVariables)
	}
	for key, value := range e.Document.Variables {
		if err := validateText("document.variables key", key, 200, true); err != nil {
			return err
		}
		if !variableNamePattern.MatchString(key) {
			return errors.New("esign: document.variables contains an invalid variable name")
		}
		if len(value) > maxVariableValue || !utf8.ValidString(value) {
			return fmt.Errorf("esign: document.variables[%q] is invalid or too large", key)
		}
	}
	if len(e.Document.Recipients) == 0 || len(e.Document.Recipients) > maxRecipients {
		return fmt.Errorf("esign: document.recipients must contain 1 to %d entries", maxRecipients)
	}
	seen := make(map[string]struct{}, len(e.Document.Recipients))
	for index, recipient := range e.Document.Recipients {
		if err := recipient.validate(index); err != nil {
			return err
		}
		identity := strings.ToLower(strings.TrimSpace(recipient.Role)) + "\x00" + strings.ToLower(strings.TrimSpace(recipient.Email))
		if _, ok := seen[identity]; ok {
			return fmt.Errorf("esign: duplicate recipient role and email at index %d", index)
		}
		seen[identity] = struct{}{}
	}
	if e.Document.ExpiresAt != nil && e.Document.ExpiresAt.Before(e.OccurredAt.Add(MinimumExpiryLead)) {
		return fmt.Errorf("esign: document.expires_at must be at least %s after occurred_at", MinimumExpiryLead)
	}
	return nil
}

func (r Recipient) validate(index int) error {
	prefix := fmt.Sprintf("document.recipients[%d]", index)
	if r.ExternalID != "" {
		if err := validateIdentifier(prefix+".external_id", r.ExternalID); err != nil {
			return err
		}
	}
	if !recipientRolePattern.MatchString(r.Role) || r.Role == "cc" || r.Role == "viewer" {
		return fmt.Errorf("esign: %s.role is not a supported response role", prefix)
	}
	if err := validateName(prefix+".name", r.Name); err != nil {
		return err
	}
	if err := validateEmail(prefix+".email", r.Email); err != nil {
		return err
	}
	if r.Locale != "" {
		if err := validateText(prefix+".locale", r.Locale, 35, true); err != nil {
			return err
		}
	}
	if r.SigningOrder < 0 || r.SigningOrder > 1000 {
		return fmt.Errorf("esign: %s.signing_order must be between 0 and 1000", prefix)
	}
	return nil
}

func validateIdentifier(field, value string) error {
	return validateText(field, value, maxIdentifierSize, true)
}

func validateName(field, value string) error {
	if err := validateText(field, value, 300, true); err != nil {
		return err
	}
	if utf8.RuneCountInString(value) > maxNameRunes {
		return fmt.Errorf("esign: %s exceeds %d Unicode code points", field, maxNameRunes)
	}
	return nil
}

func validateText(field, value string, maxBytes int, required bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("esign: %s must be valid UTF-8", field)
	}
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("esign: %s must not have surrounding whitespace", field)
	}
	if required && value == "" {
		return fmt.Errorf("esign: %s is required", field)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("esign: %s exceeds %d bytes", field, maxBytes)
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("esign: %s contains control characters", field)
		}
	}
	return nil
}

func validateEmail(field, value string) error {
	if err := validateText(field, value, maxEmailBytes, true); err != nil {
		return err
	}
	address, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(address.Address, value) {
		return fmt.Errorf("esign: %s must be a plain email address", field)
	}
	return nil
}

package esign

import (
	"strings"
	"testing"
	"time"
)

const validEvent = `{
  "spec_version":"1.0",
  "event_id":"evt-customer-42-agreement-1",
  "event_type":"esignature.document.requested.v1",
  "occurred_at":"2026-08-31T12:00:00Z",
  "source":{"provider":"brightcrm","tenant_external_id":"partner-123"},
  "customer":{"external_id":"customer-42","name":"Ada Lovelace","email":"ada@example.com"},
  "document":{
    "template_key":"sales-partner-agreement-v1",
    "name":"Partner agreement",
    "variables":{"deal.reference":"D-42"},
    "recipients":[{"external_id":"customer-42","role":"signer","name":"Ada Lovelace","email":"ada@example.com","locale":"en","signing_order":0}]
  }
}`

func TestDecodeDocumentRequested(t *testing.T) {
	t.Parallel()
	event, err := DecodeDocumentRequested([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID != "evt-customer-42-agreement-1" || event.Document.TemplateKey != "sales-partner-agreement-v1" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if got := event.Document.Recipients[0].Email; got != "ada@example.com" {
		t.Fatalf("recipient email = %q", got)
	}
}

func TestDecodeDocumentRequestedRejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := strings.Replace(validEvent, `"event_id":"evt-customer-42-agreement-1",`, `"event_id":"evt-customer-42-agreement-1","hash_base_url":"https://attacker.example",`, 1)
	if _, err := DecodeDocumentRequested([]byte(raw)); err == nil || !strings.Contains(err.Error(), "unknown JSON object member") {
		t.Fatalf("got %v, want unknown-field error", err)
	}
}

func TestDecodeDocumentRequestedRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	if _, err := DecodeDocumentRequested([]byte(validEvent + `{}`)); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("got %v, want trailing-JSON error", err)
	}
}

func TestDecodeDocumentRequestedRejectsCaseVariantAliases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "top-level alias",
			raw:  strings.Replace(validEvent, `"event_id":"evt-customer-42-agreement-1"`, `"EVENT_ID":"attacker"`, 1),
		},
		{
			name: "top-level duplicate alias",
			raw:  strings.Replace(validEvent, `"event_id":"evt-customer-42-agreement-1",`, `"event_id":"one","EVENT_ID":"two",`, 1),
		},
		{
			name: "nested recipient alias",
			raw:  strings.Replace(validEvent, `"email":"ada@example.com","locale":"en"`, `"EMAIL":"attacker@example.test","locale":"en"`, 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeDocumentRequested([]byte(test.raw))
			if err == nil || !strings.Contains(err.Error(), "unknown JSON object member") {
				t.Fatalf("got %v, want exact-name rejection", err)
			}
			if strings.Contains(err.Error(), "attacker") {
				t.Fatalf("error leaked producer-controlled value: %v", err)
			}
		})
	}
}

func TestDecodeDocumentRequestedRejectsDuplicateObjectMembers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "top-level event ID",
			raw:  strings.Replace(validEvent, `"event_id":"evt-customer-42-agreement-1",`, `"event_id":"first","event_id":"second",`, 1),
		},
		{
			name: "nested template key",
			raw:  strings.Replace(validEvent, `"template_key":"sales-partner-agreement-v1",`, `"template_key":"first","template_key":"second",`, 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeDocumentRequested([]byte(test.raw))
			if err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
				t.Fatalf("got %v, want duplicate-member error", err)
			}
			if strings.Contains(err.Error(), "event_id") || strings.Contains(err.Error(), "template_key") {
				t.Fatalf("error echoed attacker-controlled member name: %v", err)
			}
		})
	}
}

func TestDecodeDocumentRequestedRejectsDuplicateRecipient(t *testing.T) {
	t.Parallel()
	duplicate := `{"external_id":"other","role":"signer","name":"Ada","email":"ADA@example.com","signing_order":1}`
	raw := strings.Replace(validEvent, `"recipients":[`, `"recipients":[`+duplicate+`,`, 1)
	if _, err := DecodeDocumentRequested([]byte(raw)); err == nil || !strings.Contains(err.Error(), "duplicate recipient") {
		t.Fatalf("got %v, want duplicate-recipient error", err)
	}
}

func TestDecodeDocumentRequestedRejectsNonStringVariable(t *testing.T) {
	t.Parallel()
	for _, value := range []string{`42`, `null`, `true`, `{}`, `[]`} {
		raw := strings.Replace(validEvent, `"variables":{"deal.reference":"D-42"}`, `"variables":{"deal.reference":`+value+`}`, 1)
		if _, err := DecodeDocumentRequested([]byte(raw)); err == nil {
			t.Fatalf("expected non-string variable %s to fail", value)
		}
	}
}

func TestDocumentRequestedVariableNamesMatchHashTemplateSyntax(t *testing.T) {
	t.Parallel()
	event, err := DecodeDocumentRequested([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"customer_name", "contract.value", "_internal.value", "A" + strings.Repeat("a", 199)} {
		event.Document.Variables = map[string]string{key: "value"}
		if err := event.Validate(); err != nil {
			t.Errorf("valid variable name %q rejected: %v", key, err)
		}
	}
	for _, key := range []string{"9customer", "contract-value", "contract value", "contract..value-", "_" + strings.Repeat("a", 200)} {
		event.Document.Variables = map[string]string{key: "value"}
		if err := event.Validate(); err == nil {
			t.Errorf("invalid variable name %q accepted", key)
		}
	}
}

func TestDocumentRequestedIdentityBoundariesMatchHash(t *testing.T) {
	t.Parallel()
	event, err := DecodeDocumentRequested([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}

	nameAtLimit := strings.Repeat("a", 199) + string(rune(0x1F4A1))
	event.Customer.Name = nameAtLimit
	event.Document.Recipients[0].Name = nameAtLimit
	if err := event.Validate(); err != nil {
		t.Fatalf("200-code-point names rejected: %v", err)
	}
	for _, mutate := range []func(*DocumentRequested){
		func(event *DocumentRequested) { event.Customer.Name += "b" },
		func(event *DocumentRequested) { event.Document.Recipients[0].Name += "b" },
	} {
		candidate := event
		candidate.Document.Recipients = append([]Recipient(nil), event.Document.Recipients...)
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatal("201-code-point name accepted")
		}
	}

	emailAtLimit := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 185) + ".com"
	if len(emailAtLimit) != 254 {
		t.Fatalf("test email length = %d", len(emailAtLimit))
	}
	event.Customer.Name = "Ada"
	event.Document.Recipients[0].Name = "Ada"
	event.Customer.Email = emailAtLimit
	event.Document.Recipients[0].Email = emailAtLimit
	if err := event.Validate(); err != nil {
		t.Fatalf("254-byte emails rejected: %v", err)
	}
	event.Customer.Email = strings.Repeat("a", 65) + "@" + strings.Repeat("b", 185) + ".com"
	if err := event.Validate(); err == nil {
		t.Fatal("255-byte customer email accepted")
	}
	event.Customer.Email = emailAtLimit
	event.Document.Recipients[0].Email = strings.Repeat("a", 65) + "@" + strings.Repeat("b", 185) + ".com"
	if err := event.Validate(); err == nil {
		t.Fatal("255-byte recipient email accepted")
	}
}

func TestDocumentRequestedExpiryLeadIsReplayStableFromOccurredAt(t *testing.T) {
	t.Parallel()
	event, err := DecodeDocumentRequested([]byte(validEvent))
	if err != nil {
		t.Fatal(err)
	}
	tooSoon := event.OccurredAt.Add(MinimumExpiryLead - time.Nanosecond)
	event.Document.ExpiresAt = &tooSoon
	if err := event.Validate(); err == nil {
		t.Fatal("expiry below the immutable ten-minute lead was accepted")
	}
	atMinimum := event.OccurredAt.Add(MinimumExpiryLead)
	event.Document.ExpiresAt = &atMinimum
	if err := event.Validate(); err != nil {
		t.Fatalf("expiry at the immutable ten-minute lead rejected: %v", err)
	}
}

func TestDecodeDocumentRequestedUsesStrictRFC3339Syntax(t *testing.T) {
	t.Parallel()
	validOccurred := strings.Replace(validEvent,
		`"occurred_at":"2026-08-31T12:00:00Z"`,
		`"occurred_at":"2026-08-31T12:00:00.123456789+23:59"`, 1)
	if _, err := DecodeDocumentRequested([]byte(validOccurred)); err != nil {
		t.Fatalf("nine-digit fraction and +23:59 offset rejected: %v", err)
	}
	for _, timestamp := range []string{
		"2026-08-31T12:00:00.1234567890Z",
		"2026-08-31T12:00:00,1Z",
		"2026-08-31T12:00:00+24:00",
	} {
		raw := strings.Replace(validEvent, "2026-08-31T12:00:00Z", timestamp, 1)
		if _, err := DecodeDocumentRequested([]byte(raw)); err == nil {
			t.Fatalf("non-canonical RFC3339 timestamp %q accepted", timestamp)
		}
	}

	validExpiry := strings.Replace(validOccurred, `"recipients":[`,
		`"expires_at":"2026-08-31T12:10:00.123456789+23:59","recipients":[`, 1)
	if _, err := DecodeDocumentRequested([]byte(validExpiry)); err != nil {
		t.Fatalf("strict expiry boundary rejected: %v", err)
	}
}

func TestDecodeDocumentRequestedRejectsInvalidEnvelope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "version", old: `"spec_version":"1.0"`, new: `"spec_version":"2.0"`},
		{name: "type", old: `"event_type":"esignature.document.requested.v1"`, new: `"event_type":"other"`},
		{name: "email", old: `"email":"ada@example.com"`, new: `"email":"Ada <ada@example.com>"`},
		{name: "document name", old: `"name":"Partner agreement"`, new: `"name":""`},
		{name: "informational role", old: `"role":"signer"`, new: `"role":"cc"`},
		{name: "event control", old: `"event_id":"evt-customer-42-agreement-1"`, new: `"event_id":"bad\nvalue"`},
		{name: "company control", old: `"email":"ada@example.com"`, new: `"email":"ada@example.com","company_name":"bad\nvalue"`},
		{name: "phone too long", old: `"email":"ada@example.com"`, new: `"email":"ada@example.com","phone":"` + strings.Repeat("1", 65) + `"`},
		{name: "locale control", old: `"email":"ada@example.com"`, new: `"email":"ada@example.com","locale":"en\nUS"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			raw := strings.Replace(validEvent, test.old, test.new, 1)
			if _, err := DecodeDocumentRequested([]byte(raw)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

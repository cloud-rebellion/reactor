package hash

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const trustedLifecycleOrgID = "0d45a473-69aa-43a8-9000-9f14b9e1dcfe"

func lifecycleEnvelope(kind string) []byte {
	return []byte(fmt.Sprintf(`{
  "event_id":"e4bcf071-6c66-4787-8fb1-41f87f419a16",
  "kind":%q,
  "occurred_at":"2026-09-01T10:30:00.123Z",
  "org_id":%q,
  "automation_request_id":"f6a451f9-fb04-46af-8234-113113fe3a0d",
  "document":{"id":"20f574e1-dd6f-41d8-bc8a-38e088512b55"},
  "recipient":{"id":"8b384874-7114-4eb0-a843-2b2d121c5ac7"},
  "payload":{"email":"ada@example.com","nested":{"name":"Ada Lovelace"}}
}`, kind, trustedLifecycleOrgID))
}

func TestDecodeLifecycleEventAllowsDocumentKindsAndStripsProviderPayload(t *testing.T) {
	t.Parallel()
	kinds := []string{
		KindDocumentSent,
		KindDocumentOpened,
		KindDocumentViewed,
		KindDocumentFieldFilled,
		KindDocumentSigned,
		KindDocumentCompleted,
		KindDocumentDeclined,
		KindDocumentChangesRequested,
		KindDocumentVoided,
		KindDocumentExpired,
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			event, err := DecodeLifecycleEvent(lifecycleEnvelope(kind), trustedLifecycleOrgID)
			if err != nil {
				t.Fatalf("decode lifecycle event: %v", err)
			}
			if event.Kind != kind || event.EventID == "" || event.AutomationRequestID == "" || event.DocumentID == "" || event.OccurredAt.IsZero() {
				t.Fatalf("event = %+v", event)
			}
			forwarded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"org_id", "recipient", "payload", "ada@example.com", "Ada Lovelace"} {
				if strings.Contains(string(forwarded), forbidden) {
					t.Fatalf("forwarded lifecycle event retained %q: %s", forbidden, forwarded)
				}
			}
		})
	}
}

func TestProjectWebhookEventRemovesPIIBeforeRunPersistence(t *testing.T) {
	t.Parallel()
	projected, err := ProjectWebhookEvent(lifecycleEnvelope(KindDocumentSigned))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"recipient", "payload", "ada@example.com", "Ada Lovelace"} {
		if strings.Contains(string(projected), forbidden) {
			t.Fatalf("projected webhook retained %q: %s", forbidden, projected)
		}
	}
	for _, required := range []string{"event_id", "kind", "occurred_at", "org_id", "automation_request_id", "document"} {
		if !strings.Contains(string(projected), `"`+required+`"`) {
			t.Fatalf("projected webhook omitted %q: %s", required, projected)
		}
	}
	decoded, err := DecodeLifecycleEvent(projected, trustedLifecycleOrgID)
	if err != nil || decoded.Kind != KindDocumentSigned {
		t.Fatalf("projected webhook no longer decodes: %+v, %v", decoded, err)
	}
}

func TestProjectWebhookEventPreservesMissingAutomationCorrelation(t *testing.T) {
	t.Parallel()
	raw := strings.Replace(
		string(lifecycleEnvelope(KindDocumentSent)),
		`"automation_request_id":"f6a451f9-fb04-46af-8234-113113fe3a0d",`,
		"",
		1,
	)
	projected, err := ProjectWebhookEvent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(projected), "automation_request_id") {
		t.Fatalf("projection invented automation correlation: %s", projected)
	}
	if _, err := DecodeLifecycleEvent(projected, trustedLifecycleOrgID); !errors.Is(err, ErrUncorrelatedDocument) {
		t.Fatalf("projected manual event error = %v, want ErrUncorrelatedDocument", err)
	}
}

func TestDecodeLifecycleEventRejectsUntrustedAndIrrelevantEvents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		raw        []byte
		trustedOrg string
	}{
		{name: "untrusted org", raw: lifecycleEnvelope(KindDocumentSent), trustedOrg: "another-org"},
		{name: "document created", raw: lifecycleEnvelope("document.created"), trustedOrg: trustedLifecycleOrgID},
		{name: "recipient kind", raw: lifecycleEnvelope("recipient.invited"), trustedOrg: trustedLifecycleOrgID},
		{name: "unknown kind", raw: lifecycleEnvelope("ada@example.com"), trustedOrg: trustedLifecycleOrgID},
		{name: "missing trusted org", raw: lifecycleEnvelope(KindDocumentSent), trustedOrg: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeLifecycleEvent(test.raw, test.trustedOrg)
			if err == nil {
				t.Fatal("invalid lifecycle event accepted")
			}
			if strings.Contains(err.Error(), "ada@example.com") {
				t.Fatalf("validation error leaked input: %v", err)
			}
		})
	}
}

func TestDecodeLifecycleEventRequiresStrictCorrelationEnvelope(t *testing.T) {
	t.Parallel()
	valid := string(lifecycleEnvelope(KindDocumentCompleted))
	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing event ID", raw: strings.Replace(valid, `"event_id":"e4bcf071-6c66-4787-8fb1-41f87f419a16",`, "", 1)},
		{name: "missing occurred at", raw: strings.Replace(valid, `"occurred_at":"2026-09-01T10:30:00.123Z",`, "", 1)},
		{name: "missing org", raw: strings.Replace(valid, `"org_id":"`+trustedLifecycleOrgID+`",`, "", 1)},
		{name: "empty automation request", raw: strings.Replace(valid, `"automation_request_id":"f6a451f9-fb04-46af-8234-113113fe3a0d"`, `"automation_request_id":""`, 1)},
		{name: "missing document", raw: strings.Replace(valid, `"document":{"id":"20f574e1-dd6f-41d8-bc8a-38e088512b55"},`, "", 1)},
		{name: "missing document ID", raw: strings.Replace(valid, `{"id":"20f574e1-dd6f-41d8-bc8a-38e088512b55"}`, `{}`, 1)},
		{name: "unknown top field", raw: strings.Replace(valid, `"event_id":`, `"customer_email":"ada@example.com","event_id":`, 1)},
		{name: "unknown document field", raw: strings.Replace(valid, `"document":{"id":`, `"document":{"email":"ada@example.com","id":`, 1)},
		{name: "unknown recipient field", raw: strings.Replace(valid, `"recipient":{"id":`, `"recipient":{"email":"ada@example.com","id":`, 1)},
		{name: "duplicate top field", raw: strings.Replace(valid, `"kind":`, `"event_id":"duplicate","kind":`, 1)},
		{name: "duplicate payload field", raw: strings.Replace(valid, `"email":"ada@example.com"`, `"email":"ada@example.com","email":"other@example.com"`, 1)},
		{name: "trailing value", raw: valid + `{}`},
		{name: "malformed timestamp", raw: strings.Replace(valid, "2026-09-01T10:30:00.123Z", "not-a-time", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeLifecycleEvent([]byte(test.raw), trustedLifecycleOrgID)
			if err == nil {
				t.Fatal("invalid lifecycle envelope accepted")
			}
			if strings.Contains(err.Error(), "ada@example.com") || strings.Contains(err.Error(), "other@example.com") {
				t.Fatalf("decode error leaked payload data: %v", err)
			}
		})
	}
}

func TestDecodeLifecycleEventIdentifiesManualDocumentAsNoOp(t *testing.T) {
	t.Parallel()
	raw := strings.Replace(
		string(lifecycleEnvelope(KindDocumentSent)),
		`"automation_request_id":"f6a451f9-fb04-46af-8234-113113fe3a0d",`,
		"",
		1,
	)
	_, err := DecodeLifecycleEvent([]byte(raw), trustedLifecycleOrgID)
	if !errors.Is(err, ErrUncorrelatedDocument) {
		t.Fatalf("error = %v, want ErrUncorrelatedDocument", err)
	}
}

func TestDecodeLifecycleEventBoundsBody(t *testing.T) {
	t.Parallel()
	if _, err := DecodeLifecycleEvent(nil, trustedLifecycleOrgID); err == nil {
		t.Fatal("empty body accepted")
	}
	if _, err := DecodeLifecycleEvent([]byte(strings.Repeat(" ", maxWebhookEventBytes+1)), trustedLifecycleOrgID); err == nil {
		t.Fatal("oversized body accepted")
	}
	invalidUTF8 := append([]byte(`{"event_id":"`), byte(0xff))
	if _, err := DecodeLifecycleEvent(invalidUTF8, trustedLifecycleOrgID); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestLifecycleOccurredAtPreservesInstant(t *testing.T) {
	t.Parallel()
	event, err := DecodeLifecycleEvent(lifecycleEnvelope(KindDocumentOpened), trustedLifecycleOrgID)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.September, 1, 10, 30, 0, 123000000, time.UTC)
	if !event.OccurredAt.Equal(want) {
		t.Fatalf("occurred_at = %s, want %s", event.OccurredAt, want)
	}
}

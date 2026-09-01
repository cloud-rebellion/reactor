package strictjson

import (
	"encoding/json"
	"testing"
)

func TestDecodeStrictContract(t *testing.T) {
	t.Parallel()
	type nested struct {
		ID string `json:"id"`
	}
	type event struct {
		EventID string `json:"event_id"`
		Nested  nested `json:"nested"`
	}

	var got event
	if err := Decode([]byte(`{"event_id":"one","nested":{"id":"two"}}`), &got); err != nil {
		t.Fatalf("valid JSON: %v", err)
	}
	if got.EventID != "one" || got.Nested.ID != "two" {
		t.Fatalf("decoded event = %+v", got)
	}
	for _, raw := range [][]byte{
		[]byte(`{"event_id":"\uD83D\uDCA1","nested":{"id":"paired"}}`),
		[]byte(`{"event_id":"\\uD800","nested":{"id":"escaped-backslash"}}`),
	} {
		if err := Decode(raw, &event{}); err != nil {
			t.Fatalf("valid Unicode escape JSON rejected: %s: %v", raw, err)
		}
	}

	for _, raw := range [][]byte{
		[]byte(`{"event_id":"one","unknown":true,"nested":{"id":"two"}}`),
		[]byte(`{"event_id":"one","event_id":"two","nested":{"id":"two"}}`),
		[]byte(`{"event_id":"one","nested":{"id":"two","id":"three"}}`),
		[]byte(`{"EVENT_ID":"one","nested":{"id":"two"}}`),
		[]byte(`{"event_id":"one","EVENT_ID":"two","nested":{"id":"two"}}`),
		[]byte(`{"event_id":"one","nested":{"ID":"two"}}`),
		[]byte(`{"event_id":"one","nested":{"id":"two"}} {}`),
		[]byte("{\"event_id\":\"\xff\"}"),
		[]byte(`{"event_id":"\uD800","nested":{"id":"two"}}`),
		[]byte(`{"event_id":"\uDFFF","nested":{"id":"two"}}`),
		[]byte(`{"event_id":"\uD800\u0041","nested":{"id":"two"}}`),
		[]byte(`{"event_id":"\uD800\\uDC00","nested":{"id":"two"}}`),
	} {
		if err := Decode(raw, &event{}); err == nil {
			t.Fatalf("invalid JSON accepted: %q", raw)
		}
	}
}

func TestDecodeAllowsArbitraryMapKeysButStillRejectsDuplicates(t *testing.T) {
	t.Parallel()
	type envelope struct {
		Payload map[string]json.RawMessage `json:"payload"`
	}
	var got envelope
	if err := Decode([]byte(`{"payload":{"Customer.Email":"a@example.test","EVENT_ID":"opaque"}}`), &got); err != nil {
		t.Fatalf("arbitrary payload map keys rejected: %v", err)
	}
	if len(got.Payload) != 2 {
		t.Fatalf("payload = %+v", got.Payload)
	}
	if err := Decode([]byte(`{"payload":{"x":1,"x":2}}`), &envelope{}); err == nil {
		t.Fatal("duplicate arbitrary map key accepted")
	}
}

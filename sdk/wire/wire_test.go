package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	want := []Frame{
		mustWrap(t, 1, 0, KindHello, Hello{Version: Version, WorkflowSlug: "demo", RunID: "run_123", Mode: "live"}),
		mustWrap(t, 2, 0, KindStepStart, StepStart{StepName: "fetch", IdempotencyKey: "cust-1", InputHash: "abc", Attempt: 1}),
		mustWrap(t, 3, 2, KindStepReply, StepReply{Replay: false}),
		mustWrap(t, 4, 0, KindStepEnd, StepEnd{StepName: "fetch", Attempt: 1, Output: json.RawMessage(`{"id":"cus_1"}`)}),
		mustWrap(t, 5, 0, KindLog, Log{Level: "info", Msg: "hello", Attrs: map[string]any{"k": "v"}}),
		mustWrap(t, 6, 0, KindSecretFetch, SecretFetch{ID: "stripe-key"}),
		mustWrap(t, 7, 6, KindSecretReply, SecretReply{Value: []byte("sk_live_abc"), Fingerprint: "sha256:beef"}),
	}

	for _, f := range want {
		if err := enc.Encode(f); err != nil {
			t.Fatalf("encode %s: %v", f.Kind, err)
		}
	}

	for i, w := range want {
		got, err := dec.Decode()
		if err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if got.ID != w.ID || got.Reply != w.Reply || got.Kind != w.Kind {
			t.Fatalf("frame %d: header mismatch got=%+v want=%+v", i, got, w)
		}
		if string(got.Body) != string(w.Body) {
			t.Fatalf("frame %d: body mismatch got=%s want=%s", i, got.Body, w.Body)
		}
	}
}

func TestDecodeRejectsTrash(t *testing.T) {
	t.Parallel()
	const childOutput = "private-access-token-not-json"
	r := strings.NewReader(childOutput + "\n")
	dec := NewDecoder(r)
	if _, err := dec.Decode(); !errors.Is(err, ErrMalformedFrame) || strings.Contains(err.Error(), childOutput) {
		t.Fatalf("malformed child output was reflected or misclassified: %v", err)
	}
}

func TestEncodeRejectsOversize(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	huge := strings.Repeat("a", MaxFrameBytes+10)
	frame, err := Wrap(1, 0, KindLog, Log{Msg: huge})
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(frame); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func TestDecodeEOF(t *testing.T) {
	t.Parallel()
	dec := NewDecoder(strings.NewReader(""))
	if _, err := dec.Decode(); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}

func TestDecodeSkipsBlankLines(t *testing.T) {
	t.Parallel()
	r := strings.NewReader("\n\n" + `{"id":1,"kind":"ack"}` + "\n")
	dec := NewDecoder(r)
	f, err := dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != KindAck || f.ID != 1 {
		t.Fatalf("got %+v", f)
	}
}

func TestDecodeSkipsManyBlankLinesWithoutRecursion(t *testing.T) {
	t.Parallel()
	// Workflow stdout is untrusted. Keep a large blank-line run bounded to
	// ensure a noisy child cannot grow the host call stack while Decode skips
	// empty frames.
	r := strings.NewReader(strings.Repeat("\n", 200_000) + `{"id":1,"kind":"ack"}` + "\n")
	dec := NewDecoder(r)
	f, err := dec.Decode()
	if err != nil {
		t.Fatalf("Decode() error after blank-line run: %v", err)
	}
	if f.Kind != KindAck || f.ID != 1 {
		t.Fatalf("got %+v after blank-line run", f)
	}
}

func TestUnwrap(t *testing.T) {
	t.Parallel()
	f, err := Wrap(1, 0, KindStepStart, StepStart{StepName: "x", Attempt: 2})
	if err != nil {
		t.Fatal(err)
	}
	var got StepStart
	if err := Unwrap(f, &got); err != nil {
		t.Fatal(err)
	}
	if got.StepName != "x" || got.Attempt != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestUnwrapDoesNotReflectChildBody(t *testing.T) {
	const privateField = "oauth-access-token-in-field-name"
	f := Frame{Body: json.RawMessage(`{"` + privateField + `":"bad"}`)}
	var body struct {
		Value int `json:"oauth-access-token-in-field-name"`
	}
	if err := Unwrap(f, &body); !errors.Is(err, ErrMalformedBody) || strings.Contains(err.Error(), privateField) {
		t.Fatalf("malformed child body was reflected or misclassified: %v", err)
	}
}

func mustWrap(t *testing.T, id, reply int64, kind Kind, body any) Frame {
	t.Helper()
	f, err := Wrap(id, reply, kind, body)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

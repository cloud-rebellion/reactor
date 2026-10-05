package runtime

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDecodeOutputPreservesLargeInt guards the replay-divergence fix: a cached
// int64 above 2^53 must round-trip through the replay decoder exactly. Before
// UseNumber it decoded to a lossy float64 and replay diverged from the run.
func TestDecodeOutputPreservesLargeInt(t *testing.T) {
	const big int64 = 9007199254740993 // 2^53 + 1
	raw, err := json.Marshal(big)
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	num, ok := v.(json.Number)
	if !ok {
		t.Fatalf("decodeOutput returned %T, want json.Number (UseNumber)", v)
	}
	got, err := num.Int64()
	if err != nil {
		t.Fatal(err)
	}
	if got != big {
		t.Fatalf("int64 replay lost precision: got %d, want %d", got, big)
	}
}

// TestRemoteSecretRedactsEverywhere guards the SDK-side redaction: the secret
// value a workflow handles must never leak through json/text/slog/GoString,
// since those flow into run logs readable via the dashboard + MCP.
func TestRemoteSecretRedactsEverywhere(t *testing.T) {
	const plaintext = "hunter2-plaintext"
	s := &remoteSecret{value: []byte(plaintext), fingerprint: "abc123"}

	if got := s.String(); got != "[REDACTED]" {
		t.Errorf("String() = %q", got)
	}
	if got := s.GoString(); got != "[REDACTED]" {
		t.Errorf("GoString() = %q", got)
	}
	if got := s.LogValue().String(); got != "[REDACTED]" {
		t.Errorf("LogValue() = %q", got)
	}
	txt, _ := s.MarshalText()
	if string(txt) != "[REDACTED]" {
		t.Errorf("MarshalText() = %q", txt)
	}
	// A struct embedding the secret must not leak plaintext through json.Marshal
	// (the common "logged/encoded a config struct" mistake).
	b, err := json.Marshal(struct {
		Key *remoteSecret `json:"key"`
	}{s})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), plaintext) {
		t.Fatalf("json.Marshal leaked secret plaintext: %s", b)
	}
	// Reveal is the one explicit, greppable escape hatch that still works.
	if string(s.Reveal()) != plaintext {
		t.Error("Reveal() should return the real value")
	}
	got := s.Reveal()
	got[0] = 'X'
	if string(s.Reveal()) != plaintext {
		t.Errorf("mutating Reveal result changed cached remote secret: %q", s.Reveal())
	}
}

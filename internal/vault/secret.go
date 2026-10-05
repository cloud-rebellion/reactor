package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
)

// Secret wraps a credential value so it cannot accidentally leak through
// String, fmt, JSON, text marshallers, or slog. The plaintext is reachable
// only via Reveal, which is a deliberate, greppable function call.
//
// Defense-in-depth pairs with the Postgres role split: even if a buggy log
// or JSON encode reaches a *Secret, the redaction kicks in.
type Secret struct {
	value []byte
}

// NewSecret takes a defensive copy of plaintext. Callers should zero
// their own buffer after constructing a Secret if they care.
func NewSecret(plaintext []byte) *Secret {
	cp := make([]byte, len(plaintext))
	copy(cp, plaintext)
	return &Secret{value: cp}
}

// Reveal returns a defensive copy of the plaintext. This is the only path to
// it; every other method redacts. Returning a copy keeps workflow code from
// mutating the cached value that other concurrent runs may use, while still
// making the deliberate runtime escape greppable and easy to ban from
// non-runtime packages via build-tag-controlled lint rules.
func (s *Secret) Reveal() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.value...)
}

// Fingerprint returns the first 8 bytes of SHA-256(value), hex-encoded.
// Useful for "is this same key wired to two workflows?" without exposing
// the value. Surfaced via the MCP credential metadata API.
func (s *Secret) Fingerprint() string {
	if s == nil || len(s.value) == 0 {
		return ""
	}
	sum := sha256.Sum256(s.value)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// String redacts. Always.
func (s *Secret) String() string { return "[REDACTED]" }

// GoString redacts. Always.
func (s *Secret) GoString() string { return "[REDACTED]" }

// MarshalJSON redacts. Always.
func (s *Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// MarshalText redacts. Always.
func (s *Secret) MarshalText() ([]byte, error) {
	return []byte("[REDACTED]"), nil
}

// LogValue redacts. Slog respects this.
func (s *Secret) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}

package payloadcrypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestEnvelopeBindsTenantRunAndPurpose(t *testing.T) {
	key, err := New(bytes.Repeat([]byte{0x5a}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"private":"not-on-disk"}`)
	id := Identity("tenant-a", "run-1", "trigger_meta")
	sealed, err := key.SealJSON(plain, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("not-on-disk")) || !bytes.Contains(sealed, []byte("__reactor_payload_envelope")) {
		t.Fatalf("invalid sealed journal payload: %s", sealed)
	}
	got, encrypted, err := key.OpenJSON(sealed, id)
	if err != nil || !encrypted || !bytes.Equal(got, plain) {
		t.Fatalf("open = %q, encrypted=%v, err=%v", got, encrypted, err)
	}
	for _, other := range [][]byte{
		Identity("tenant-b", "run-1", "trigger_meta"),
		Identity("tenant-a", "run-2", "trigger_meta"),
		Identity("tenant-a", "run-1", "trigger_input"),
	} {
		if _, _, err := key.OpenJSON(sealed, other); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("copy under another identity: %v", err)
		}
	}
	broken := bytes.Replace(sealed, []byte("__reactor_payload_envelope"), []byte("__reactor_payload_envelope"), 1)
	broken[len(broken)-4] ^= 1
	if _, _, err := key.OpenJSON(broken, id); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("tampered envelope: %v", err)
	}
	if _, _, err := (*Keyring)(nil).OpenJSON(sealed, id); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestLegacyAndRotation(t *testing.T) {
	first, _ := New(bytes.Repeat([]byte{1}, 32), nil)
	rotated, _ := New(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{1}, 32))
	id := Identity("tenant", "run", "trigger_input")
	legacy := []byte(`{"id":1}`)
	if got, encrypted, err := rotated.OpenBytes(legacy, id); err != nil || encrypted || !bytes.Equal(got, legacy) {
		t.Fatalf("legacy bytes = %q, encrypted=%v, err=%v", got, encrypted, err)
	}
	sealed, _ := first.SealBytes(legacy, id)
	if got, encrypted, err := rotated.OpenBytes(sealed, id); err != nil || !encrypted || !bytes.Equal(got, legacy) {
		t.Fatalf("previous key = %q, encrypted=%v, err=%v", got, encrypted, err)
	}
	if _, _, err := (*Keyring)(nil).OpenBytes(sealed, id); !errors.Is(err, ErrKeyRequired) {
		t.Fatalf("encrypted without key: %v", err)
	}
	if _, _, err := rotated.OpenBytes([]byte("reactor-payload:v2:garbage"), id); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("unknown version: %v", err)
	}
	if JSONCiphertextLimit(len(legacy)) < len(mustSealJSON(t, rotated, legacy, id)) || CiphertextLimit(len(legacy)) < len(sealed) {
		t.Fatal("ciphertext bound too small")
	}
	if strings.Contains(string(sealed), string(legacy)) {
		t.Fatal("input leaked in ciphertext")
	}
}

func mustSealJSON(t *testing.T, key *Keyring, value, identity []byte) []byte {
	t.Helper()
	sealed, err := key.SealJSON(value, identity)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

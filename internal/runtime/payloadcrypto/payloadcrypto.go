// Package payloadcrypto seals execution data before it enters the journal.
// A dedicated HKDF subkey separates run data from the credential vault. Its
// input is the stable, random journal data key wrapped by the daemon master.
package payloadcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	keySize       = 32
	nonceSize     = 12
	textPrefix    = "reactor-payload:v1:"
	reservedField = "__reactor_payload_envelope"
	keyPurpose    = "reactor/journal/payload/aes-256-gcm/v1"
)

var (
	ErrKeyRequired     = errors.New("journal payload: encryption key required")
	ErrInvalidEnvelope = errors.New("journal payload: invalid encrypted envelope")
)

// Keyring opens envelopes written with the current key or, during a rotation
// window, one previous key. Every new write uses the current key. Old rows
// must be re-sealed before the previous key can be retired.
type Keyring struct {
	current  [keySize]byte
	previous *[keySize]byte
}

func New(master, previous []byte) (*Keyring, error) {
	if len(master) != keySize || (len(previous) != 0 && len(previous) != keySize) {
		return nil, ErrKeyRequired
	}
	k := &Keyring{}
	if err := derive(&k.current, master); err != nil {
		return nil, err
	}
	if len(previous) != 0 {
		k.previous = new([keySize]byte)
		if err := derive(k.previous, previous); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func derive(dst *[keySize]byte, master []byte) error {
	_, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte(keyPurpose)), dst[:])
	return err
}

// Identity binds a value to its tenant, run, and purpose. The length-prefixed
// components are unambiguous even if an imported identifier contains a
// separator. A copied ciphertext cannot authenticate under another column or
// run, and changing a run's tenant makes its old payload unreadable.
func Identity(tenantID, runID, purpose string) []byte {
	var out []byte
	for _, value := range []string{tenantID, runID, purpose} {
		out = append(out, byte(len(value)>>24), byte(len(value)>>16), byte(len(value)>>8), byte(len(value)))
		out = append(out, value...)
	}
	return out
}

func (k *Keyring) SealBytes(plain, identity []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrKeyRequired
	}
	block, err := aes.NewCipher(k.current[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("journal payload: nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce[:], plain, identity)
	encoded := make([]byte, len(textPrefix)+base64.RawURLEncoding.EncodedLen(nonceSize+len(ciphertext)))
	copy(encoded, textPrefix)
	base64.RawURLEncoding.Encode(encoded[len(textPrefix):], append(nonce[:], ciphertext...))
	return encoded, nil
}

// OpenBytes passes through explicitly legacy plaintext. Once a versioned
// prefix is seen, malformed data, a missing key, or failed authentication is
// always an error; none of those cases silently fall back to plaintext.
func (k *Keyring) OpenBytes(stored, identity []byte) ([]byte, bool, error) {
	if !IsByteEnvelope(stored) {
		return append([]byte(nil), stored...), false, nil
	}
	if k == nil {
		return nil, true, ErrKeyRequired
	}
	if !bytes.HasPrefix(stored, []byte(textPrefix)) {
		return nil, true, ErrInvalidEnvelope
	}
	encoded := stored[len(textPrefix):]
	if len(encoded) < base64.RawURLEncoding.EncodedLen(nonceSize+16) {
		return nil, true, ErrInvalidEnvelope
	}
	blob := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	n, err := base64.RawURLEncoding.Decode(blob, encoded)
	if err != nil || n < nonceSize+16 {
		return nil, true, ErrInvalidEnvelope
	}
	blob = blob[:n]
	for _, key := range []*[keySize]byte{&k.current, k.previous} {
		if key == nil {
			continue
		}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, true, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, true, err
		}
		if plain, err := gcm.Open(nil, blob[:nonceSize], blob[nonceSize:], identity); err == nil {
			return plain, true, nil
		}
	}
	return nil, true, ErrInvalidEnvelope
}

func IsByteEnvelope(stored []byte) bool { return bytes.HasPrefix(stored, []byte("reactor-payload:")) }

// SealJSON keeps PostgreSQL JSONB and SQLite TEXT columns valid JSON while
// concealing their original shape and values. The reserved one-field object
// is a storage format, never supplied to workflow code or MCP export.
func (k *Keyring) SealJSON(plain, identity []byte) ([]byte, error) {
	ciphertext, err := k.SealBytes(plain, identity)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{reservedField: string(ciphertext)})
}

func (k *Keyring) OpenJSON(stored, identity []byte) ([]byte, bool, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(stored, &object); err != nil || object == nil {
		return append([]byte(nil), stored...), false, nil
	}
	raw, present := object[reservedField]
	if !present {
		return append([]byte(nil), stored...), false, nil
	}
	if len(object) != 1 {
		return nil, true, ErrInvalidEnvelope
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, true, ErrInvalidEnvelope
	}
	plain, encrypted, err := k.OpenBytes([]byte(encoded), identity)
	if err != nil {
		return nil, true, err
	}
	if !encrypted {
		return nil, true, ErrInvalidEnvelope
	}
	return plain, true, nil
}

// CiphertextLimit is an upper bound for one binary envelope whose plaintext
// is at most plainLimit bytes. Control-plane SQL can use this before loading
// and authenticating a bounded value.
func CiphertextLimit(plainLimit int) int {
	return len(textPrefix) + base64.RawURLEncoding.EncodedLen(nonceSize+plainLimit+16)
}

// PostgreSQL JSONB inserts a separator space when rendered as text. Reserve
// a small fixed margin for that canonical form; the post-decrypt plaintext
// length remains the authoritative bound.
func JSONCiphertextLimit(plainLimit int) int {
	return CiphertextLimit(plainLimit) + len(reservedField) + 64
}

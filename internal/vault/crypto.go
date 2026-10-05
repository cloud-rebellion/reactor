// Package secrets owns the credential vault: encryption primitives, the
// leak-resistant Secret type, the in-process atomic.Pointer cache, and the
// rotation state machine. Everything that touches plaintext lives here.
//
// Crypto choices (locked in DECISIONS.md, mirroring Dockyard):
//
//	AES-256-GCM, PBKDF2-SHA256 600,000 iterations, 32-byte salt per secret,
//	12-byte nonce per encryption, version byte prefix for forward compat.
//
// Stored format:
//
//	[version(1)] [salt(32)] [nonce(12)] [ciphertext(...)]
//
// The version byte enables transparent re-encryption on read after a master-key
// rotation: v2 blobs authenticate the credential identity as AES-GCM
// associated data, while legacy v1 blobs remain readable and migrate lazily.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// VersionV1 is the format byte for the v1 blob layout.
	VersionV1 byte = 0x01
	// VersionV2 binds a blob to its credential identifier through AES-GCM's
	// associated-data field. The v1 format remains readable for lazy migration,
	// but new vault writes use v2 so copying an encrypted row to another
	// credential cannot make the value decrypt there.
	VersionV2 byte = 0x02

	saltLen     = 32
	nonceLen    = 12
	gcmTagLen   = 16
	keyLen      = 32 // AES-256
	pbkdf2Iters = 600_000
)

// ErrInvalidBlob is returned when a blob is malformed (too short or
// has an unknown version byte).
var ErrInvalidBlob = errors.New("secrets: invalid encrypted blob")

// ErrInvalidMasterKey is returned when the master key length is wrong.
var ErrInvalidMasterKey = errors.New("secrets: master key must be 32 bytes")

// Encrypt encrypts plaintext with a unique salt + nonce and returns
// the v1 blob layout: [version][salt][nonce][ciphertext].
func Encrypt(masterKey, plaintext []byte) ([]byte, error) {
	return encrypt(masterKey, plaintext, VersionV1, nil)
}

// EncryptForID seals a credential value and binds it to id. A ciphertext
// copied between credential rows will fail authentication when read under a
// different identifier. The id is authenticated as associated data and is not
// included in the ciphertext payload.
func EncryptForID(masterKey []byte, id string, plaintext []byte) ([]byte, error) {
	if id == "" {
		return nil, errors.New("secrets: credential id required")
	}
	return encrypt(masterKey, plaintext, VersionV2, []byte(id))
}

func encrypt(masterKey, plaintext []byte, version byte, aad []byte) ([]byte, error) {
	if len(masterKey) != keyLen {
		return nil, ErrInvalidMasterKey
	}
	if len(plaintext) > MaxSecretBytes {
		return nil, ErrSecretTooLarge
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("secrets: salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secrets: nonce: %w", err)
	}

	dek := deriveKey(masterKey, salt)
	defer zero(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("secrets: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, 1+saltLen+nonceLen+len(ct))
	out = append(out, version)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt reverses Encrypt. Returns ErrInvalidBlob if the version byte
// or layout is wrong, or any underlying GCM error if the key is wrong
// or the data was tampered with.
func Decrypt(masterKey, blob []byte) ([]byte, error) {
	return decrypt(masterKey, blob, nil)
}

// DecryptForID opens a credential-bound v2 blob under the exact id used when
// it was sealed. v1 blobs are accepted for compatibility and migration, but
// are intentionally not treated as id-bound because they carry no identity
// in their authenticated data.
func DecryptForID(masterKey []byte, id string, blob []byte) ([]byte, error) {
	if id == "" {
		return nil, errors.New("secrets: credential id required")
	}
	return decrypt(masterKey, blob, []byte(id))
}

func decrypt(masterKey, blob, aad []byte) ([]byte, error) {
	if len(masterKey) != keyLen {
		return nil, ErrInvalidMasterKey
	}
	if len(blob) < 1+saltLen+nonceLen {
		return nil, ErrInvalidBlob
	}
	// Reject an oversized ciphertext before GCM allocates and authenticates a
	// potentially attacker-controlled plaintext buffer. Store reads already
	// enforce the same bound; keeping it here protects direct decrypt callers.
	if len(blob) > 1+saltLen+nonceLen+gcmTagLen+MaxSecretBytes {
		return nil, ErrSecretTooLarge
	}
	openAAD := []byte(nil)
	switch blob[0] {
	case VersionV1:
	case VersionV2:
		if len(aad) == 0 {
			return nil, fmt.Errorf("%w: credential id required for version 0x%02x", ErrInvalidBlob, blob[0])
		}
		openAAD = aad
	default:
		return nil, fmt.Errorf("%w: unsupported version 0x%02x", ErrInvalidBlob, blob[0])
	}
	salt := blob[1 : 1+saltLen]
	nonce := blob[1+saltLen : 1+saltLen+nonceLen]
	ct := blob[1+saltLen+nonceLen:]

	dek := deriveKey(masterKey, salt)
	defer zero(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("secrets: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return gcm.Open(nil, nonce, ct, openAAD)
}

// deriveKey runs PBKDF2-HMAC-SHA256 with the locked-in iteration count.
// Each call allocates a fresh derived-key slice the caller is responsible
// for zeroing.
func deriveKey(masterKey, salt []byte) []byte {
	return pbkdf2.Key(masterKey, salt, pbkdf2Iters, keyLen, sha256.New)
}

// zero overwrites the slice contents. Best-effort: Go's GC may have
// copied the data elsewhere already, but doing this for derived keys
// shrinks the residency window noticeably under pressure.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

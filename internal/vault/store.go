package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ErrNotFound is returned when a credential ID is not provisioned.
var ErrNotFound = errors.New("vault: credential not found")

// MaxSecretBytes bounds the plaintext held in the runtime credential path.
// Vault values are injected into an isolated command environment and copied
// for output redaction, so an unbounded value could turn one credential into a
// memory and journal-redaction amplification vector. 64 KiB covers ordinary
// API keys, certificates, and small credentials while keeping per-step copies
// bounded (the command plan itself allows at most 32 references).
const MaxSecretBytes = 64 << 10

// ErrSecretTooLarge is returned before an oversized value is encrypted or
// materialized. Existing oversized rows fail closed when first read so a
// legacy value cannot bypass the bound.
var ErrSecretTooLarge = errors.New("vault: credential value exceeds maximum size")

// Backend persists encrypted blobs. Implementations live under
// internal/vault/backend/ (sqlite, postgres). Week 2 ships an in-memory
// backend; the SQL backends land alongside the rest of the vault schema
// in week 8.
type Backend interface {
	Put(ctx context.Context, id string, blob []byte) error
	Get(ctx context.Context, id string) ([]byte, error) // returns ErrNotFound if missing
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]string, error)
}

// Store is the in-process credential cache + the hot-swap point.
//
// Reads (MustGet, Get) are lock-free pointer loads off an atomic.Pointer
// per credential. Rotation calls swap() once; readers always observe the
// latest value. Goroutines holding a previous *Secret finish their
// in-flight call with the old value, which is exactly what the rotation
// state machine's dual-validity window protects.
type Store struct {
	backend  Backend
	master   []byte
	previous []byte       // optional prior master key for the rotation window
	mu       sync.RWMutex // guards the map shape (insert/delete), not pointer reads
	cache    map[string]*atomic.Pointer[Secret]
	watchers map[string][]chan struct{}
}

// NewStore wires a backend + a master key. An optional previous master key
// enables a rotation window: blobs still encrypted under the previous key are
// decrypted with it and lazily re-encrypted under the current key on read, so
// rotating REACTOR_MASTER_KEY (with the old value in REACTOR_MASTER_KEY_PREVIOUS)
// does not brick the vault. Pass at most one previous key.
func NewStore(backend Backend, masterKey []byte, previous ...[]byte) (*Store, error) {
	if len(masterKey) != keyLen {
		return nil, ErrInvalidMasterKey
	}
	if backend == nil {
		return nil, errors.New("secrets: backend required")
	}
	s := &Store{
		backend:  backend,
		master:   append([]byte(nil), masterKey...),
		cache:    map[string]*atomic.Pointer[Secret]{},
		watchers: map[string][]chan struct{}{},
	}
	if len(previous) > 0 && len(previous[0]) == keyLen {
		s.previous = append([]byte(nil), previous[0]...)
	}
	return s, nil
}

// Put encrypts plaintext, persists the blob, and primes the cache so
// the next MustGet returns without a DB round trip.
func (s *Store) Put(ctx context.Context, id string, plaintext []byte) error {
	if id == "" {
		return errors.New("secrets: id required")
	}
	if len(plaintext) > MaxSecretBytes {
		return ErrSecretTooLarge
	}
	blob, err := EncryptForID(s.master, id, plaintext)
	if err != nil {
		return err
	}
	if err := s.backend.Put(ctx, id, blob); err != nil {
		return fmt.Errorf("secrets: backend put: %w", err)
	}
	s.swap(id, NewSecret(plaintext))
	return nil
}

// Get returns the current Secret, loading + decrypting on first access.
// Subsequent calls hit the atomic pointer and never touch the backend
// or the cipher.
func (s *Store) Get(ctx context.Context, id string) (*Secret, error) {
	if p := s.load(id); p != nil {
		return p, nil
	}
	return s.loadFromBackend(ctx, id)
}

// MustGet panics if the credential is unset. Workflow code calls this
// at step boundaries; a missing credential is a fatal misconfiguration
// and the runtime's panic recovery surfaces it as a workflow failure.
func (s *Store) MustGet(ctx context.Context, id string) *Secret {
	v, err := s.Get(ctx, id)
	if err != nil {
		panic(fmt.Sprintf("vault.MustGet(%q): %v", id, err))
	}
	return v
}

// Watch returns a channel that closes when the credential is rotated.
// Long-lived consumers (DB pools authed with rotating passwords) can
// subscribe and rebuild on signal. One-shot: the channel is consumed
// and replaced on the next swap.
func (s *Store) Watch(id string) <-chan struct{} {
	ch := make(chan struct{})
	s.mu.Lock()
	s.watchers[id] = append(s.watchers[id], ch)
	s.mu.Unlock()
	return ch
}

// Rotate replaces the value for id without a restart. Callers should
// have already verified the new value with the upstream service via
// the rotator's Verify hook.
func (s *Store) Rotate(ctx context.Context, id string, newPlaintext []byte) error {
	return s.Put(ctx, id, newPlaintext)
}

// Delete removes a credential from both backend and cache.
func (s *Store) Delete(ctx context.Context, id string) error {
	if err := s.backend.Delete(ctx, id); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.cache, id)
	for _, ch := range s.watchers[id] {
		close(ch)
	}
	delete(s.watchers, id)
	s.mu.Unlock()
	return nil
}

// load returns the current pointer or nil if uncached.
func (s *Store) load(id string) *Secret {
	s.mu.RLock()
	p, ok := s.cache[id]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return p.Load()
}

// loadFromBackend decrypts on demand, populates the cache, and returns.
func (s *Store) loadFromBackend(ctx context.Context, id string) (*Secret, error) {
	blob, err := s.backend.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	plaintext, err := DecryptForID(s.master, id, blob)
	if err != nil {
		// Rotation window: a blob still sealed under the previous master key
		// decrypts with it; re-encrypt it under the current key on read
		// (transparent re-encryption) so a master-key rotation migrates the
		// vault lazily instead of leaving every secret undecryptable.
		if len(s.previous) == keyLen {
			if pt, pErr := DecryptForID(s.previous, id, blob); pErr == nil {
				if len(pt) > MaxSecretBytes {
					zero(pt)
					return nil, ErrSecretTooLarge
				}
				if reblob, eErr := EncryptForID(s.master, id, pt); eErr == nil {
					_ = s.backend.Put(ctx, id, reblob) // best-effort; retried next read
				}
				sec := NewSecret(pt)
				zero(pt)
				s.swap(id, sec)
				return sec, nil
			}
		}
		return nil, fmt.Errorf("secrets: decrypt %q: %w", id, err)
	}
	if len(plaintext) > MaxSecretBytes {
		zero(plaintext)
		return nil, ErrSecretTooLarge
	}
	// v1 blobs predate credential-bound associated data. Keep them readable for
	// compatibility, but migrate them on first access so a later row swap is
	// rejected by the v2 identity binding. A transient backend write failure is
	// safe: the value is still returned and the next uncached read retries it.
	if len(blob) > 0 && blob[0] == VersionV1 {
		if reblob, reErr := EncryptForID(s.master, id, plaintext); reErr == nil {
			_ = s.backend.Put(ctx, id, reblob)
		}
	}
	sec := NewSecret(plaintext)
	zero(plaintext)
	s.swap(id, sec)
	return sec, nil
}

// swap stores the new pointer atomically and fans out to watchers.
//
// Critical: p.Store happens INSIDE the critical section so a Watch() call
// interleaved between the cache snapshot and the pointer store cannot
// subscribe AND observe a stale value with no notification coming. The
// reader path (s.load) is still lock-free; readers only need RLock for
// the map shape, then atomic.Pointer.Load for the value.
func (s *Store) swap(id string, sec *Secret) {
	s.mu.Lock()
	p, ok := s.cache[id]
	if !ok {
		p = &atomic.Pointer[Secret]{}
		s.cache[id] = p
	}
	watchers := s.watchers[id]
	s.watchers[id] = nil
	p.Store(sec)
	s.mu.Unlock()

	for _, ch := range watchers {
		close(ch)
	}
}

package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// flashStore carries one-time secret material across a POST -> GET redirect.
// With a journal backend, separate Reactor replicas share the encrypted row;
// the random HttpOnly cookie is both the lookup capability and the only input
// from which its encryption key can be derived. The database stores only a
// domain-separated token digest and AES-GCM ciphertext.
//
// Tests and deliberately minimal servers without a journal retain the same
// single-process behavior through the in-memory fallback.
type flashStore struct {
	backend       flashBackend
	secureCookies bool

	mu  sync.Mutex
	m   map[string]flashEntry
	ttl time.Duration
}

type flashBackend interface {
	PutOneTimeFlash(context.Context, string, []byte, time.Time) error
	TakeOneTimeFlash(context.Context, string) ([]byte, time.Time, error)
	PurgeExpiredOneTimeFlashes(context.Context, time.Time) error
}

type flashEntry struct {
	ciphertext []byte
	expires    time.Time
}

const (
	flashCookieName = "reactor_flash"
	flashMaxBytes   = 64 << 10
	flashVersion    = byte(1)
)

var (
	flashLookupDomain = []byte("reactor/one-time-flash/lookup/v1\x00")
	flashKeyDomain    = []byte("reactor/one-time-flash/key/v1\x00")
)

func newFlashStore(backends ...flashBackend) *flashStore {
	var backend flashBackend
	if len(backends) > 0 {
		backend = backends[0]
	}
	return &flashStore{
		backend: backend,
		m:       map[string]flashEntry{},
		ttl:     5 * time.Minute,
	}
}

// put encrypts payload under a fresh browser-held capability and writes that
// capability to a short-lived HttpOnly cookie. No raw token or payload is
// persisted by the shared backend.
func (s *flashStore) put(w http.ResponseWriter, r *http.Request, payload map[string]string) error {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 || len(plaintext) > flashMaxBytes {
		return errors.New("flash payload is empty or too large")
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	tokenHash := flashTokenHash(tokenBytes)
	ciphertext, err := sealFlash(tokenBytes, tokenHash, plaintext)
	if err != nil {
		return err
	}
	expires := time.Now().UTC().Add(s.ttl)
	if s.backend != nil {
		// Opportunistic cleanup is best effort; failure to purge an older row
		// must not hide the just-created secret from this redirect.
		_ = s.backend.PurgeExpiredOneTimeFlashes(r.Context(), time.Now().UTC())
		if err := s.backend.PutOneTimeFlash(r.Context(), tokenHash, ciphertext, expires); err != nil {
			return err
		}
	} else {
		s.mu.Lock()
		s.m[tokenHash] = flashEntry{ciphertext: ciphertext, expires: expires}
		s.gcLocked()
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies || r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.ttl.Seconds()),
	})
	return nil
}

// take atomically consumes and decrypts the payload, then clears the browser
// capability. Any malformed, expired, tampered, missing, or replayed cookie is
// indistinguishable to the page and yields no secret.
func (s *flashStore) take(w http.ResponseWriter, r *http.Request) map[string]string {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	// Any response reached with a flash capability may render a raw API token
	// or HMAC secret. Prevent browsers and shared intermediaries from retaining
	// either the successful reveal or an error page associated with it.
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies || r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	tokenBytes, err := hex.DecodeString(cookie.Value)
	if err != nil || len(tokenBytes) != 32 || hex.EncodeToString(tokenBytes) != cookie.Value {
		return nil
	}
	tokenHash := flashTokenHash(tokenBytes)
	var entry flashEntry
	if s.backend != nil {
		entry.ciphertext, entry.expires, err = s.backend.TakeOneTimeFlash(r.Context(), tokenHash)
		if err != nil {
			return nil
		}
	} else {
		s.mu.Lock()
		var ok bool
		entry, ok = s.m[tokenHash]
		delete(s.m, tokenHash)
		s.mu.Unlock()
		if !ok {
			return nil
		}
	}
	if time.Now().UTC().After(entry.expires) {
		return nil
	}
	plaintext, err := openFlash(tokenBytes, tokenHash, entry.ciphertext)
	if err != nil || len(plaintext) == 0 || len(plaintext) > flashMaxBytes {
		return nil
	}
	var payload map[string]string
	if err := json.Unmarshal(plaintext, &payload); err != nil || payload == nil {
		return nil
	}
	return payload
}

func flashTokenHash(token []byte) string {
	h := sha256.New()
	_, _ = h.Write(flashLookupDomain)
	_, _ = h.Write(token)
	return hex.EncodeToString(h.Sum(nil))
}

func flashKey(token []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(flashKeyDomain)
	_, _ = h.Write(token)
	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	return key
}

func sealFlash(token []byte, tokenHash string, plaintext []byte) ([]byte, error) {
	key := flashKey(token)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 1, 1+len(nonce)+len(plaintext)+gcm.Overhead())
	out[0] = flashVersion
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, []byte(tokenHash))
	return out, nil
}

func openFlash(token []byte, tokenHash string, ciphertext []byte) ([]byte, error) {
	key := flashKey(token)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+gcm.NonceSize()+gcm.Overhead() || ciphertext[0] != flashVersion {
		return nil, errors.New("invalid flash ciphertext")
	}
	nonce := ciphertext[1 : 1+gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[1+gcm.NonceSize():], []byte(tokenHash))
}

func (s *flashStore) gcLocked() {
	now := time.Now().UTC()
	for key, entry := range s.m {
		if now.After(entry.expires) {
			delete(s.m, key)
		}
	}
}

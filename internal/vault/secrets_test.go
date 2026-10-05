package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	key := mustKey(t)
	cases := []struct {
		name string
		pt   []byte
	}{
		{"short", []byte("hi")},
		{"binary", []byte{0, 1, 2, 0xff, 0xfe}},
		{"empty", []byte{}},
		{"long", bytes.Repeat([]byte("abc"), 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := Encrypt(key, tc.pt)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if blob[0] != VersionV1 {
				t.Fatalf("version byte = 0x%02x, want 0x01", blob[0])
			}
			got, err := Decrypt(key, blob)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, tc.pt) {
				t.Fatalf("round trip mismatch: got %q, want %q", got, tc.pt)
			}
		})
	}
}

func TestEncryptUniqueOutputForSamePlaintext(t *testing.T) {
	t.Parallel()
	key := mustKey(t)
	pt := []byte("identical")
	a, err := Encrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext should differ (salt + nonce)")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	t.Parallel()
	pt := []byte("abc")
	good := mustKey(t)
	bad := mustKey(t)
	blob, err := Encrypt(good, pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(bad, blob); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestCredentialBoundEncryptionRejectsCiphertextSwap(t *testing.T) {
	t.Parallel()
	key := mustKey(t)
	pt := []byte("bound-secret")
	blob, err := EncryptForID(key, "cred-a", pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("encrypted credential blob contains plaintext")
	}
	if got, err := DecryptForID(key, "cred-a", blob); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("decrypt with original id: got=%q err=%v", got, err)
	}
	if _, err := DecryptForID(key, "cred-b", blob); err == nil {
		t.Fatal("ciphertext copied to another credential id decrypted successfully")
	}
	if _, err := Decrypt(key, blob); err == nil {
		t.Fatal("credential-bound v2 blob decrypted through unbound API")
	}
}

func TestDecryptTampered(t *testing.T) {
	t.Parallel()
	key := mustKey(t)
	blob, err := Encrypt(key, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	// flip a bit deep in the ciphertext.
	blob[len(blob)-1] ^= 0x01
	if _, err := Decrypt(key, blob); err == nil {
		t.Fatal("decrypt of tampered blob should fail GCM auth")
	}
}

func TestDecryptInvalidBlobs(t *testing.T) {
	t.Parallel()
	key := mustKey(t)
	cases := [][]byte{
		nil,
		{},
		{0x01},
		make([]byte, 1+saltLen+nonceLen-1),
		append([]byte{0xff}, make([]byte, saltLen+nonceLen+16)...),
	}
	for i, b := range cases {
		if _, err := Decrypt(key, b); err == nil {
			t.Fatalf("case %d: want error for malformed blob", i)
		}
	}
}

func TestDecryptInvalidMasterKey(t *testing.T) {
	t.Parallel()
	if _, err := Decrypt(make([]byte, 31), nil); err == nil {
		t.Fatal("31-byte key should fail")
	}
	if _, err := Encrypt(make([]byte, 31), []byte("x")); err == nil {
		t.Fatal("31-byte key should fail")
	}
}

func TestSecretRedactsAcrossSurfaces(t *testing.T) {
	t.Parallel()
	s := NewSecret([]byte("super-secret-value"))

	// fmt.Sprintf %v / %s / %+v / %#v should never leak.
	for _, verb := range []string{"%v", "%s", "%+v", "%#v", "%q"} {
		got := fmt.Sprintf(verb, s)
		if strings.Contains(got, "super-secret-value") {
			t.Fatalf("verb %s leaked: %q", verb, got)
		}
	}

	// JSON: must serialise as the redaction string.
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if string(b) != `"[REDACTED]"` {
		t.Fatalf("json marshal = %s, want \"[REDACTED]\"", b)
	}

	// Slog: text handler should redact.
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	logger := slog.New(h)
	logger.Info("test", "secret", s)
	if strings.Contains(buf.String(), "super-secret-value") {
		t.Fatalf("slog leaked: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "[REDACTED]") {
		t.Fatalf("slog did not redact: %s", buf.String())
	}

	// Reveal must still return the plaintext.
	if string(s.Reveal()) != "super-secret-value" {
		t.Fatalf("Reveal = %q, want %q", s.Reveal(), "super-secret-value")
	}
}

func TestSecretRevealDoesNotExposeCachedBackingBytes(t *testing.T) {
	t.Parallel()
	s := NewSecret([]byte("super-secret-value"))
	got := s.Reveal()
	got[0] = 'X'
	if string(s.Reveal()) != "super-secret-value" {
		t.Fatalf("mutating Reveal result changed cached secret: %q", s.Reveal())
	}
}

func TestSecretFingerprintStable(t *testing.T) {
	t.Parallel()
	a := NewSecret([]byte("xyz"))
	b := NewSecret([]byte("xyz"))
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("identical plaintexts must produce identical fingerprints")
	}
	c := NewSecret([]byte("xyzz"))
	if a.Fingerprint() == c.Fingerprint() {
		t.Fatal("different plaintexts must produce different fingerprints")
	}
	if !strings.HasPrefix(a.Fingerprint(), "sha256:") {
		t.Fatalf("fingerprint missing prefix: %s", a.Fingerprint())
	}
}

func TestStorePutGet(t *testing.T) {
	t.Parallel()
	store, err := NewStore(NewMemoryBackend(), mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := store.Put(ctx, "stripe-key", []byte("sk_live_abc")); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "stripe-key")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Reveal()) != "sk_live_abc" {
		t.Fatalf("got %q", got.Reveal())
	}
}

func TestStoreBoundsAndBindsPlaintextAtRest(t *testing.T) {
	t.Parallel()
	backend := NewMemoryBackend()
	store, err := NewStore(backend, mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Put(ctx, "cred-a", []byte("secret-a")); err != nil {
		t.Fatal(err)
	}
	blob, err := backend.Get(ctx, "cred-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 || blob[0] != VersionV2 || bytes.Contains(blob, []byte("secret-a")) {
		t.Fatalf("stored credential blob is not bound encrypted data: version=%x blob=%q", blob[0], blob)
	}
	if err := store.Put(ctx, "too-large", bytes.Repeat([]byte("x"), MaxSecretBytes+1)); !errors.Is(err, ErrSecretTooLarge) {
		t.Fatalf("oversized credential put error=%v, want ErrSecretTooLarge", err)
	}
}

func TestStoreMigratesUnboundV1BlobToCredentialBoundV2(t *testing.T) {
	t.Parallel()
	backend := NewMemoryBackend()
	key := mustKey(t)
	legacy, err := Encrypt(key, []byte("legacy-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Put(context.Background(), "cred-legacy", legacy); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(backend, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get(context.Background(), "cred-legacy"); err != nil || string(got.Reveal()) != "legacy-secret" {
		t.Fatalf("legacy read: got=%v err=%v", got, err)
	}
	migrated, err := backend.Get(context.Background(), "cred-legacy")
	if err != nil {
		t.Fatal(err)
	}
	if len(migrated) == 0 || migrated[0] != VersionV2 {
		t.Fatalf("legacy blob was not migrated to v2: version=%x", migrated[0])
	}
}

func TestStoreGetMissing(t *testing.T) {
	t.Parallel()
	store, _ := NewStore(NewMemoryBackend(), mustKey(t))
	if _, err := store.Get(context.Background(), "nope"); err == nil {
		t.Fatal("missing credential should error")
	}
}

func TestStoreDecryptOnFirstAccessAfterRestart(t *testing.T) {
	t.Parallel()
	// Simulate a restart: same backend bytes, fresh Store.
	backend := NewMemoryBackend()
	key := mustKey(t)
	{
		s, _ := NewStore(backend, key)
		_ = s.Put(context.Background(), "k", []byte("v1"))
	}
	s2, _ := NewStore(backend, key)
	got, err := s2.Get(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Reveal()) != "v1" {
		t.Fatalf("got %q after restart", got.Reveal())
	}
}

// TestStoreMasterKeyRotationWindow proves the two-key rotation window: a secret
// sealed under the old master key is transparently decrypted with the previous
// key and re-encrypted under the new key on read, so rotating the master key
// migrates the vault lazily instead of bricking it.
func TestStoreMasterKeyRotationWindow(t *testing.T) {
	t.Parallel()
	backend := NewMemoryBackend()
	oldKey := mustKey(t)
	newKey := mustKey(t)
	ctx := context.Background()

	// Seal a secret under the OLD key.
	{
		s, _ := NewStore(backend, oldKey)
		if err := s.Put(ctx, "k", []byte("secret-v1")); err != nil {
			t.Fatal(err)
		}
	}

	// Rotate: new primary + old as previous. The blob is still under oldKey, so
	// the window must decrypt via previous and re-encrypt under new.
	rotated, err := NewStore(backend, newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rotated.Get(ctx, "k")
	if err != nil || string(got.Reveal()) != "secret-v1" {
		t.Fatalf("rotation-window read: got %v, err %v", got, err)
	}

	// The read lazily re-encrypted under newKey: a fresh store with ONLY newKey
	// (no previous) must now decrypt it.
	fresh, _ := NewStore(backend, newKey)
	if got2, err := fresh.Get(ctx, "k"); err != nil || string(got2.Reveal()) != "secret-v1" {
		t.Fatalf("secret not re-encrypted under new key: got %v, err %v", got2, err)
	}

	// And it must NO LONGER decrypt under the old key alone (migration is real).
	oldOnly, _ := NewStore(backend, oldKey)
	if _, err := oldOnly.Get(ctx, "k"); err == nil {
		t.Fatal("secret should not decrypt under the old key after migration")
	}
}

func TestStoreHotSwap(t *testing.T) {
	t.Parallel()
	store, _ := NewStore(NewMemoryBackend(), mustKey(t))
	ctx := context.Background()
	if err := store.Put(ctx, "k", []byte("v1")); err != nil {
		t.Fatal(err)
	}

	// Subscribe before rotating.
	ch := store.Watch("k")

	if err := store.Rotate(ctx, "k", []byte("v2")); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ch:
		// expected: watcher fired
	default:
		t.Fatal("watcher not notified on rotation")
	}

	got, _ := store.Get(ctx, "k")
	if string(got.Reveal()) != "v2" {
		t.Fatalf("after rotate got %q, want v2", got.Reveal())
	}
}

func TestStoreConcurrentReadDuringRotate(t *testing.T) {
	t.Parallel()
	store, _ := NewStore(NewMemoryBackend(), mustKey(t))
	ctx := context.Background()
	if err := store.Put(ctx, "k", []byte("v1")); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := atomic.Bool{}

	// 8 concurrent readers should observe a non-empty value at all times.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				v, err := store.Get(ctx, "k")
				if err != nil {
					t.Errorf("get during rotate: %v", err)
					return
				}
				if len(v.Reveal()) == 0 {
					t.Errorf("empty value observed mid-rotate")
					return
				}
			}
		}()
	}

	// Hammer enough rotations to exercise the swap path under reader contention.
	// PBKDF2-SHA256 600k iterations is intentionally expensive, so a small
	// hammer count is plenty; the race detector validates lock-free reads.
	const rotations = 30
	for i := 0; i < rotations; i++ {
		val := fmt.Sprintf("v%d", i+2)
		if err := store.Rotate(ctx, "k", []byte(val)); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()

	final, _ := store.Get(ctx, "k")
	want := fmt.Sprintf("v%d", rotations+1)
	if string(final.Reveal()) != want {
		t.Fatalf("final value = %q, want %s", final.Reveal(), want)
	}
}

// TestStoreSwapAtomicity exercises the critical invariant that a Watch()
// subscriber can never observe a stale value while holding an open watch
// channel. Bug history: an earlier implementation released the mu lock
// before the atomic.Pointer.Store, opening a window where Watch could
// register, then Get could read v_old, while the swap finished outside
// the lock and never notified the new watcher.
//
// The watch deadline is generous because Rotate goes through Put which
// calls Encrypt, and PBKDF2-SHA256 600k iterations under the race detector
// can take several seconds per call on busy hardware. We're testing the
// happens-before relationship, not throughput.
func TestStoreSwapAtomicity(t *testing.T) {
	// Intentionally NOT parallel: the test spawns 8 rounds of concurrent
	// Rotate + Watch + Get against a single store and asserts strict
	// channel-fire timing. Running it alongside the package's other
	// t.Parallel tests on contended CI cores starves the scheduler and
	// the watch channel send misses its deadline. Serializing this one
	// test against the rest of the package eliminates the flake without
	// changing the test's actual semantics.
	store, _ := NewStore(NewMemoryBackend(), mustKey(t))
	ctx := context.Background()

	if err := store.Put(ctx, "k", []byte("v1")); err != nil {
		t.Fatal(err)
	}

	const (
		rounds = 8
		// 60s tolerance: under -race + parallel workload the Go scheduler
		// can delay channel sends well past 15s on busy CI. The test only
		// asserts "watch eventually fires after a stale read"; widening
		// the deadline keeps that semantic guarantee while ending the
		// flakes that wedge the package run on Forgejo runners.
		watchTimeout = 60 * time.Second
	)

	for round := 0; round < rounds; round++ {
		want := fmt.Sprintf("v%d", round+2)

		// Goroutine A rotates.
		// Goroutine B subscribes + reads, expecting either:
		//   (a) old value + ch will fire, or
		//   (b) new value + ch may or may not fire.
		// Forbidden: old value + ch never fires.
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if err := store.Rotate(ctx, "k", []byte(want)); err != nil {
				t.Errorf("rotate: %v", err)
			}
		}()

		go func() {
			defer wg.Done()
			ch := store.Watch("k")
			sec, err := store.Get(ctx, "k")
			if err != nil {
				t.Errorf("get: %v", err)
				return
			}
			val := string(sec.Reveal())
			if val == want {
				return // (b): saw new value, fine
			}
			// (a): saw old value, ch must eventually fire.
			select {
			case <-ch:
				return
			case <-time.After(watchTimeout):
				t.Errorf("round %d: stale value %q observed without watch firing within %s", round, val, watchTimeout)
			}
		}()

		wg.Wait()
	}
}

func TestStoreDelete(t *testing.T) {
	t.Parallel()
	store, _ := NewStore(NewMemoryBackend(), mustKey(t))
	ctx := context.Background()
	_ = store.Put(ctx, "k", []byte("v"))

	ch := store.Watch("k")
	if err := store.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	// Watch channel should close on delete (rotation event semantically).
	select {
	case <-ch:
	default:
		t.Fatal("watcher not closed on delete")
	}

	if _, err := store.Get(ctx, "k"); err == nil {
		t.Fatal("get after delete should fail")
	}
}

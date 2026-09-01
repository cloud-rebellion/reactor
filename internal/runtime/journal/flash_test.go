package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/reactor/internal/migrate"
)

func TestOneTimeFlashIsAtomicAndPurgeable(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	if err := j.PutOneTimeFlash(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []byte("ciphertext-a"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, expires, err := j.TakeOneTimeFlash(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ciphertext-a" || !expires.Equal(now.Add(time.Minute)) {
		t.Fatalf("take = %q/%s", got, expires)
	}
	if _, _, err := j.TakeOneTimeFlash(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take = %v, want ErrNotFound", err)
	}

	if err := j.PutOneTimeFlash(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", []byte("expired"), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := j.PurgeExpiredOneTimeFlashes(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.TakeOneTimeFlash(ctx, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged take = %v, want ErrNotFound", err)
	}
}

func TestOneTimeFlashPostgres(t *testing.T) {
	rawURL := os.Getenv("REACTOR_TEST_POSTGRES_URL")
	if rawURL == "" {
		t.Skip("set REACTOR_TEST_POSTGRES_URL to run the PostgreSQL flash contract")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := migrate.Up(ctx, log, rawURL); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	db, engine, err := migrate.Open(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if engine != migrate.EnginePostgres {
		t.Fatalf("REACTOR_TEST_POSTGRES_URL selected %s, want postgres", engine)
	}
	j := New(db, EnginePostgres)
	digest := sha256.Sum256([]byte(t.Name() + time.Now().UTC().String()))
	tokenHash := hex.EncodeToString(digest[:])
	expiresAt := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	if err := j.PutOneTimeFlash(ctx, tokenHash, []byte("postgres-ciphertext"), expiresAt); err != nil {
		t.Fatal(err)
	}
	ciphertext, gotExpiry, err := j.TakeOneTimeFlash(ctx, tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) != "postgres-ciphertext" || !gotExpiry.Equal(expiresAt) {
		t.Fatalf("take = %q/%s, want postgres-ciphertext/%s", ciphertext, gotExpiry, expiresAt)
	}
	if _, _, err := j.TakeOneTimeFlash(ctx, tokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take = %v, want ErrNotFound", err)
	}
}

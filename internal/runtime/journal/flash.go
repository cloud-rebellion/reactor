package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PutOneTimeFlash stores an already-encrypted, short-lived dashboard payload.
// tokenHash is a lookup digest; the browser-held token needed to decrypt the
// ciphertext is never written to the database.
func (j *Journal) PutOneTimeFlash(ctx context.Context, tokenHash string, ciphertext []byte, expiresAt time.Time) error {
	if tokenHash == "" || len(ciphertext) == 0 || expiresAt.IsZero() {
		return errors.New("journal: invalid one-time flash")
	}
	const q = `INSERT INTO one_time_flashes (token_hash, ciphertext, expires_at)
		VALUES ($1, $2, $3)`
	if _, err := j.db.ExecContext(ctx, j.bind(q), tokenHash, ciphertext, j.formatTime(expiresAt.UTC())); err != nil {
		return fmt.Errorf("journal: put one-time flash: %w", err)
	}
	return nil
}

// TakeOneTimeFlash atomically consumes a payload. DELETE ... RETURNING makes
// concurrent GETs and separate Reactor replicas agree on one winner.
func (j *Journal) TakeOneTimeFlash(ctx context.Context, tokenHash string) ([]byte, time.Time, error) {
	const q = `DELETE FROM one_time_flashes WHERE token_hash = $1
		RETURNING ciphertext, expires_at`
	var ciphertext []byte
	row := j.db.QueryRowContext(ctx, j.bind(q), tokenHash)
	if j.engine == EnginePostgres {
		var expiresAt time.Time
		if err := row.Scan(&ciphertext, &expiresAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, time.Time{}, ErrNotFound
			}
			return nil, time.Time{}, fmt.Errorf("journal: take one-time flash: %w", err)
		}
		return ciphertext, expiresAt.UTC(), nil
	}
	var expiresRaw sql.NullString
	if err := row.Scan(&ciphertext, &expiresRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, time.Time{}, ErrNotFound
		}
		return nil, time.Time{}, fmt.Errorf("journal: take one-time flash: %w", err)
	}
	if !expiresRaw.Valid {
		return nil, time.Time{}, errors.New("journal: one-time flash has no expiry")
	}
	expiresAt, err := j.parseTime(expiresRaw.String)
	if err != nil {
		return nil, time.Time{}, err
	}
	return ciphertext, expiresAt, nil
}

// PurgeExpiredOneTimeFlashes bounds rows abandoned when an operator never
// follows the redirect. It is safe to call opportunistically from flash puts.
func (j *Journal) PurgeExpiredOneTimeFlashes(ctx context.Context, now time.Time) error {
	const q = `DELETE FROM one_time_flashes WHERE expires_at <= $1`
	if _, err := j.db.ExecContext(ctx, j.bind(q), j.formatTime(now.UTC())); err != nil {
		return fmt.Errorf("journal: purge one-time flashes: %w", err)
	}
	return nil
}

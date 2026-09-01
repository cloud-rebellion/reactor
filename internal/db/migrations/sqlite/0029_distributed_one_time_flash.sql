-- +goose Up
-- One-time dashboard secrets must survive a load-balanced POST -> GET redirect
-- without being readable from the database. The browser-held random flash
-- token derives the encryption key; only its SHA-256 lookup digest is stored.
CREATE TABLE one_time_flashes (
    token_hash  TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    ciphertext BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX one_time_flashes_expires_idx ON one_time_flashes(expires_at);

-- +goose Down
DROP TABLE one_time_flashes;

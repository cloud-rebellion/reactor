-- +goose Up
-- +goose StatementBegin

-- Durable at-least-once terminal side-effect receipts. The run status and
-- this receipt are committed together; a daemon crash before notification or
-- chain dispatch can therefore be recovered by the leader loop.
CREATE TABLE terminal_effects (
    run_id       TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    claimed_at   TEXT,
    delivered_at TEXT,
    last_error   TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX terminal_effects_pending_idx
    ON terminal_effects(delivered_at, claimed_at, created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS terminal_effects_pending_idx;
DROP TABLE IF EXISTS terminal_effects;
-- +goose StatementEnd

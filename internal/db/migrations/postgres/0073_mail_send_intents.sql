-- +goose Up
-- +goose StatementBegin

-- An admitted provider write is never retried automatically. The host records
-- this row before egress; if it dies before confirmation, replay is ambiguous
-- and needs manual reconciliation. No message, recipient, or token is stored.
CREATE TABLE mail_send_intents (
    id                      TEXT PRIMARY KEY,
    run_id                  TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    step_name               TEXT NOT NULL CHECK (length(step_name) BETWEEN 1 AND 512),
    seq                     BIGINT NOT NULL CHECK (seq > 0),
    attempt                 INTEGER NOT NULL CHECK (attempt > 0),
    idempotency_key_sha256  TEXT NOT NULL CHECK (length(idempotency_key_sha256) = 64),
    request_sha256          TEXT NOT NULL CHECK (length(request_sha256) = 64),
    status                  TEXT NOT NULL CHECK (status IN ('admitted', 'confirmed')),
    provider_id             TEXT CHECK (provider_id IS NULL OR length(provider_id) BETWEEN 1 AND 128),
    message_id              TEXT CHECK (message_id IS NULL OR length(message_id) BETWEEN 1 AND 512),
    created_at              TIMESTAMPTZ NOT NULL,
    confirmed_at            TIMESTAMPTZ,
    UNIQUE (run_id, seq),
    CHECK ((status = 'admitted' AND provider_id IS NULL AND message_id IS NULL AND confirmed_at IS NULL)
        OR (status = 'confirmed' AND provider_id IS NOT NULL AND confirmed_at IS NOT NULL))
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS mail_send_intents;
-- +goose StatementEnd

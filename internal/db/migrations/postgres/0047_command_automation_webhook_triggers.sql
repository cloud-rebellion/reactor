-- +goose Up
-- +goose StatementBegin

-- Dedicated webhook bindings for command automations. These rows are kept
-- separate from `triggers`: workflow dispatch and command dispatch have
-- different admission contracts and must never share a token lookup path.
-- The row contains only immutable-version/receipt metadata and a vault
-- credential reference; request bodies and secret values are never stored.
CREATE TABLE command_automation_webhook_triggers (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    automation_id       TEXT NOT NULL REFERENCES command_automations(id) ON DELETE RESTRICT,
    automation_version  INTEGER NOT NULL,
    definition_sha256   TEXT NOT NULL,
    receipt_id          TEXT NOT NULL,
    gate_digest         TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    token_id            TEXT NOT NULL,
    secret_id           TEXT NOT NULL,
    provider            TEXT NOT NULL DEFAULT 'generic',
    state               TEXT NOT NULL DEFAULT 'disabled',
    revision            BIGINT NOT NULL DEFAULT 1,
    last_fired_at       TIMESTAMPTZ,
    last_error          TEXT,
    idempotency_key     TEXT,
    idempotency_hash    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id),
    UNIQUE (token_id)
);
CREATE INDEX command_automation_webhook_tenant_state_idx
    ON command_automation_webhook_triggers(tenant_id, state, automation_id, created_at, id);
CREATE UNIQUE INDEX command_automation_webhook_idempotency_idx
    ON command_automation_webhook_triggers(tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_automation_webhook_idempotency_idx;
DROP INDEX IF EXISTS command_automation_webhook_tenant_state_idx;
DROP TABLE IF EXISTS command_automation_webhook_triggers;
-- +goose StatementEnd

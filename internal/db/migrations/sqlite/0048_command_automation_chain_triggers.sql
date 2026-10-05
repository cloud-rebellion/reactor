-- +goose Up
-- +goose StatementBegin

-- Tenant-scoped terminal-chain bindings for command plans. This table is
-- intentionally separate from `triggers`: that table points at workflow
-- rows and its dispatch path executes workflow artifacts. A command chain
-- stores only an immutable command-plan/admission binding plus the source
-- workflow identity; no command text, input, credential, or output is copied.
CREATE TABLE command_automation_chain_triggers (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    automation_id       TEXT NOT NULL REFERENCES command_automations(id) ON DELETE RESTRICT,
    automation_version  INTEGER NOT NULL,
    definition_sha256   TEXT NOT NULL,
    receipt_id          TEXT NOT NULL,
    gate_digest         TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    source_workflow_id  TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    on_statuses         TEXT NOT NULL DEFAULT 'succeeded',
    -- New command chains are parked until an explicit receipt-bound state
    -- mutation. A source terminal event can never activate a new row merely
    -- because the create request returned successfully.
    state               TEXT NOT NULL DEFAULT 'disabled',
    revision            INTEGER NOT NULL DEFAULT 1,
    last_fired_at       TEXT,
    last_error          TEXT,
    idempotency_key     TEXT,
    idempotency_hash    TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (id, tenant_id)
);
CREATE INDEX command_automation_chain_tenant_state_idx
    ON command_automation_chain_triggers(tenant_id, state, source_workflow_id, created_at, id);
CREATE UNIQUE INDEX command_automation_chain_idempotency_idx
    ON command_automation_chain_triggers(tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_automation_chain_idempotency_idx;
DROP INDEX IF EXISTS command_automation_chain_tenant_state_idx;
DROP TABLE IF EXISTS command_automation_chain_triggers;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- Tenant-scoped cron schedules for command plans. A schedule carries only the
-- immutable plan/admission binding and cron metadata; command text, output, and
-- credentials remain in the reviewed command-plan/journal surfaces.
CREATE TABLE command_automation_schedules (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    automation_id       TEXT NOT NULL REFERENCES command_automations(id) ON DELETE RESTRICT,
    automation_version  INTEGER NOT NULL,
    definition_sha256   TEXT NOT NULL,
    receipt_id          TEXT NOT NULL,
    gate_digest         TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    spec                TEXT NOT NULL,
    timezone            TEXT NOT NULL DEFAULT 'UTC',
    -- New schedules are parked until an explicit receipt-bound activation.
    state               TEXT NOT NULL DEFAULT 'disabled',
    revision            BIGINT NOT NULL DEFAULT 1,
    last_fired_at       TIMESTAMPTZ,
    last_error          TEXT,
    idempotency_key     TEXT,
    idempotency_hash    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (id, tenant_id)
);
CREATE INDEX command_automation_schedules_tenant_state_idx
    ON command_automation_schedules(tenant_id, state, automation_id, created_at, id);
CREATE UNIQUE INDEX command_automation_schedules_idempotency_idx
    ON command_automation_schedules(tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_automation_schedules_idempotency_idx;
DROP INDEX IF EXISTS command_automation_schedules_tenant_state_idx;
DROP TABLE IF EXISTS command_automation_schedules;
-- +goose StatementEnd

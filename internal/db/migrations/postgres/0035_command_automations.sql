-- +goose Up
-- +goose StatementBegin

-- Safe command-automation core: declarative, versioned data only. Execution is
-- deliberately absent; a future runner must satisfy the separate command-step
-- gates before it can consume these rows.
CREATE TABLE command_automations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    target          TEXT NOT NULL DEFAULT '',
    current_version INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX command_automations_tenant_idx ON command_automations(tenant_id, name);

CREATE TABLE command_automation_versions (
    automation_id TEXT NOT NULL REFERENCES command_automations(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    definition_json JSONB NOT NULL,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (automation_id, version)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS command_automation_versions;
DROP INDEX IF EXISTS command_automations_tenant_idx;
DROP TABLE IF EXISTS command_automations;
-- +goose StatementEnd

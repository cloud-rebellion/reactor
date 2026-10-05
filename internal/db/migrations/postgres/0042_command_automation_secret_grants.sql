-- +goose Up
-- +goose StatementBegin

-- Explicit per-command-plan credential ACL. Command automations have their own
-- identity and lifecycle, so they must never inherit workflow grants. The
-- credential_id is intentionally not a foreign key: a reference may name an
-- OAuth connection using the separate "oauth:<id>" namespace.
CREATE TABLE command_automation_secret_grants (
    automation_id TEXT NOT NULL REFERENCES command_automations(id) ON DELETE CASCADE,
    tenant_id     TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by    TEXT,
    note          TEXT,
    PRIMARY KEY (automation_id, credential_id)
);

-- Tenant + credential lookups support admission checks without loading an
-- estate-wide ACL. The journal still verifies both resource owners before
-- writing or returning a grant, so this index is not an authorization check.
CREATE INDEX command_automation_secret_grants_tenant_credential_idx
    ON command_automation_secret_grants(tenant_id, credential_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_automation_secret_grants_tenant_credential_idx;
DROP TABLE IF EXISTS command_automation_secret_grants;
-- +goose StatementEnd

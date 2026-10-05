-- +goose Up
-- +goose StatementBegin

-- Encrypted credential vault. The blob is [version][salt][nonce][ciphertext]
-- per internal/secrets/crypto.go. Metadata columns are safe to expose via
-- the MCP server; the blob never is.
CREATE TABLE credentials (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    name            TEXT NOT NULL,
    service         TEXT NOT NULL,
    rotation_policy TEXT NOT NULL DEFAULT 'auto',  -- auto | manual | none
    blob            BLOB NOT NULL,
    upstream_handle TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    expires_at      TEXT,
    deleted_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (tenant_id, name)
);

CREATE INDEX credentials_service_idx
    ON credentials(service)
    WHERE deleted_at IS NULL;

CREATE INDEX credentials_expires_idx
    ON credentials(expires_at)
    WHERE deleted_at IS NULL;

-- Append-only credential-management audit log. Runtime SecretFetch receives
-- its own vault/OAuth-capable receipt table in migration 0051.
CREATE TABLE credential_audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL REFERENCES credentials(id),
    action        TEXT NOT NULL,    -- read | write | rotate | revoke | view_metadata
    actor_kind    TEXT NOT NULL,    -- user | workflow | scheduler | mcp
    actor_id      TEXT,
    workflow_id   TEXT,
    run_id        TEXT,
    step_id       TEXT,
    detail        TEXT NOT NULL DEFAULT '{}',
    at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX credential_audit_cred_at_idx
    ON credential_audit(credential_id, at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS credential_audit_cred_at_idx;
DROP TABLE IF EXISTS credential_audit;
DROP INDEX IF EXISTS credentials_expires_idx;
DROP INDEX IF EXISTS credentials_service_idx;
DROP TABLE IF EXISTS credentials;
-- +goose StatementEnd

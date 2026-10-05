-- +goose Up
-- +goose StatementBegin

-- One append-only receipt per authorized runtime secret fetch, for both vault
-- credentials and OAuth connections. No value, token, fingerprint, or request
-- payload is stored. Run deletion cascades as part of retention/tenant erasure.
CREATE TABLE runtime_secret_access_audit (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 512),
    workflow_id TEXT NOT NULL CHECK (length(workflow_id) BETWEEN 1 AND 512),
    run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE CHECK (length(run_id) BETWEEN 1 AND 512),
    secret_ref  TEXT NOT NULL CHECK (length(secret_ref) BETWEEN 1 AND 512),
    secret_kind TEXT NOT NULL CHECK (secret_kind IN ('vault', 'oauth')),
    at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX runtime_secret_access_audit_tenant_at_idx
    ON runtime_secret_access_audit(tenant_id, at DESC, id DESC);
CREATE INDEX runtime_secret_access_audit_run_at_idx
    ON runtime_secret_access_audit(run_id, at DESC, id DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runtime_secret_access_audit_run_at_idx;
DROP INDEX IF EXISTS runtime_secret_access_audit_tenant_at_idx;
DROP TABLE IF EXISTS runtime_secret_access_audit;
-- +goose StatementEnd

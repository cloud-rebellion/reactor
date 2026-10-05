-- +goose Up
-- +goose StatementBegin
-- Account keys are host-derived hashes of provider identities. Keep the
-- connection-level budget tables for in-flight receipts and rollback.
CREATE TABLE provider_shared_account_budgets (
    tenant_id         TEXT NOT NULL,
    provider_id       TEXT NOT NULL,
    account_key       TEXT NOT NULL CHECK (length(account_key) = 64),
    requests_per_min  INTEGER NOT NULL CHECK (requests_per_min BETWEEN 1 AND 600),
    max_concurrent    INTEGER NOT NULL CHECK (max_concurrent BETWEEN 1 AND 32),
    cooldown_until    TEXT,
    PRIMARY KEY (tenant_id, provider_id, account_key)
);

CREATE TABLE provider_shared_account_permits (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    provider_id          TEXT NOT NULL,
    account_key          TEXT NOT NULL,
    source_connection_id TEXT NOT NULL,
    granted_at           TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    completed_at         TEXT,
    FOREIGN KEY (tenant_id, provider_id, account_key)
        REFERENCES provider_shared_account_budgets(tenant_id, provider_id, account_key) ON DELETE CASCADE
);
CREATE INDEX provider_shared_account_permits_window_idx
    ON provider_shared_account_permits(tenant_id, provider_id, account_key, granted_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS provider_shared_account_permits;
DROP TABLE IF EXISTS provider_shared_account_budgets;
-- +goose StatementEnd

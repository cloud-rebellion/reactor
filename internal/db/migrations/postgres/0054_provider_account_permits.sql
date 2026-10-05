-- +goose Up
-- +goose StatementBegin
-- One policy row serializes request admission for an OAuth connection across
-- workers. Permits retain a rolling-minute receipt and a short in-flight lease.
CREATE TABLE provider_account_budgets (
    tenant_id         TEXT NOT NULL,
    connection_id     TEXT NOT NULL REFERENCES oauth_connections(id) ON DELETE CASCADE,
    requests_per_min  INTEGER NOT NULL CHECK (requests_per_min BETWEEN 1 AND 600),
    max_concurrent    INTEGER NOT NULL CHECK (max_concurrent BETWEEN 1 AND 32),
    cooldown_until    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, connection_id)
);

CREATE TABLE provider_account_permits (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    connection_id     TEXT NOT NULL,
    granted_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    completed_at      TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, connection_id)
        REFERENCES provider_account_budgets(tenant_id, connection_id) ON DELETE CASCADE
);
CREATE INDEX provider_account_permits_window_idx
    ON provider_account_permits(tenant_id, connection_id, granted_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS provider_account_permits;
DROP TABLE IF EXISTS provider_account_budgets;
-- +goose StatementEnd

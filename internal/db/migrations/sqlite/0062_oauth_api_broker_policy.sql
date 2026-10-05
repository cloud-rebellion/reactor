-- +goose Up
-- +goose StatementBegin

ALTER TABLE oauth_connections ADD COLUMN token_access_mode TEXT NOT NULL DEFAULT 'broker_only'
    CHECK (token_access_mode IN ('legacy_raw', 'broker_only'));
ALTER TABLE oauth_connections ADD COLUMN legacy_raw_reason TEXT NOT NULL DEFAULT ''
    CHECK (legacy_raw_reason IN ('', 'grandfathered', 'email_adapter'));
UPDATE oauth_connections SET token_access_mode = 'legacy_raw' WHERE provider_id <> 'salesforce';
UPDATE oauth_connections SET legacy_raw_reason = 'grandfathered' WHERE token_access_mode = 'legacy_raw';
ALTER TABLE runtime_secret_access_audit ADD COLUMN policy_revision INTEGER
    CHECK (policy_revision IS NULL OR policy_revision > 0);
ALTER TABLE oauth_states ADD COLUMN requested_scopes TEXT NOT NULL DEFAULT '';

CREATE TABLE oauth_api_policies (
    connection_id TEXT PRIMARY KEY REFERENCES oauth_connections(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    api_origin TEXT NOT NULL,
    path_prefix TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method = 'GET'),
    reviewed_by TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX oauth_api_policies_tenant_idx ON oauth_api_policies(tenant_id, connection_id);

CREATE TABLE oauth_api_policy_reviews (
    connection_id TEXT NOT NULL REFERENCES oauth_connections(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    api_origin TEXT NOT NULL,
    path_prefix TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method = 'GET'),
    reviewed_by TEXT NOT NULL,
    reviewed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (connection_id, version)
);

CREATE TRIGGER oauth_broker_mode_no_downgrade_trigger
    BEFORE UPDATE OF token_access_mode ON oauth_connections
    WHEN OLD.token_access_mode = 'broker_only' AND NEW.token_access_mode <> 'broker_only'
BEGIN
    SELECT RAISE(ABORT, 'broker-only OAuth connections cannot become raw-token eligible');
END;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE oauth_broker_downgrade_guard (n INTEGER NOT NULL CHECK (n = 0));
INSERT INTO oauth_broker_downgrade_guard
    SELECT COUNT(*) FROM oauth_connections WHERE provider_id <> 'salesforce' AND token_access_mode = 'broker_only';
DROP TABLE oauth_broker_downgrade_guard;
DROP TRIGGER IF EXISTS oauth_broker_mode_no_downgrade_trigger;
DROP TABLE IF EXISTS oauth_api_policy_reviews;
DROP INDEX IF EXISTS oauth_api_policies_tenant_idx;
DROP TABLE IF EXISTS oauth_api_policies;
ALTER TABLE runtime_secret_access_audit DROP COLUMN policy_revision;
ALTER TABLE oauth_states DROP COLUMN requested_scopes;
ALTER TABLE oauth_connections DROP COLUMN legacy_raw_reason;
ALTER TABLE oauth_connections DROP COLUMN token_access_mode;
-- +goose StatementEnd

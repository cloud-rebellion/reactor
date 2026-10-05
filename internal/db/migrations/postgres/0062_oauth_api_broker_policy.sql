-- +goose Up
-- +goose StatementBegin

-- Existing generic connections retain their explicitly grandfathered raw
-- access. New connections start broker-only and cannot silently fall back to
-- raw tokens when a review is absent or later removed.
ALTER TABLE oauth_connections ADD COLUMN token_access_mode TEXT NOT NULL DEFAULT 'broker_only'
    CHECK (token_access_mode IN ('legacy_raw', 'broker_only'));
ALTER TABLE oauth_connections ADD COLUMN legacy_raw_reason TEXT NOT NULL DEFAULT ''
    CHECK (legacy_raw_reason IN ('', 'grandfathered', 'email_adapter'));
UPDATE oauth_connections SET token_access_mode = 'legacy_raw' WHERE provider_id <> 'salesforce';
UPDATE oauth_connections SET legacy_raw_reason = 'grandfathered' WHERE token_access_mode = 'legacy_raw';
ALTER TABLE runtime_secret_access_audit ADD COLUMN policy_revision BIGINT
    CHECK (policy_revision IS NULL OR policy_revision > 0);
ALTER TABLE oauth_states ADD COLUMN requested_scopes TEXT NOT NULL DEFAULT '';

CREATE TABLE oauth_api_policies (
    connection_id TEXT PRIMARY KEY REFERENCES oauth_connections(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    api_origin TEXT NOT NULL,
    path_prefix TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method = 'GET'),
    reviewed_by TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX oauth_api_policies_tenant_idx ON oauth_api_policies(tenant_id, connection_id);

CREATE TABLE oauth_api_policy_reviews (
    connection_id TEXT NOT NULL REFERENCES oauth_connections(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    api_origin TEXT NOT NULL,
    path_prefix TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method = 'GET'),
    reviewed_by TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (connection_id, version)
);

CREATE FUNCTION oauth_broker_mode_no_downgrade() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.token_access_mode = 'broker_only' AND NEW.token_access_mode <> 'broker_only' THEN
        RAISE EXCEPTION 'broker-only OAuth connections cannot become raw-token eligible';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_broker_mode_no_downgrade_trigger
    BEFORE UPDATE OF token_access_mode ON oauth_connections
    FOR EACH ROW EXECUTE FUNCTION oauth_broker_mode_no_downgrade();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_connections WHERE provider_id <> 'salesforce' AND token_access_mode = 'broker_only') THEN
        RAISE EXCEPTION 'cannot downgrade broker-only OAuth connections to raw-token access';
    END IF;
END;
$$;
DROP TRIGGER IF EXISTS oauth_broker_mode_no_downgrade_trigger ON oauth_connections;
DROP FUNCTION IF EXISTS oauth_broker_mode_no_downgrade();
DROP TABLE IF EXISTS oauth_api_policy_reviews;
DROP INDEX IF EXISTS oauth_api_policies_tenant_idx;
DROP TABLE IF EXISTS oauth_api_policies;
ALTER TABLE runtime_secret_access_audit DROP COLUMN policy_revision;
ALTER TABLE oauth_states DROP COLUMN requested_scopes;
ALTER TABLE oauth_connections DROP COLUMN legacy_raw_reason;
ALTER TABLE oauth_connections DROP COLUMN token_access_mode;
-- +goose StatementEnd

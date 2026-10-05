-- +goose Up
-- Routing IDs are non-secret and identify the account to inspect when a
-- pre-egress intent remains ambiguous. Existing 0073 rows remain unknown.
ALTER TABLE mail_send_intents ADD COLUMN target_provider_id TEXT
    CHECK (target_provider_id IS NULL OR target_provider_id IN ('google', 'microsoft'));
ALTER TABLE mail_send_intents ADD COLUMN target_connection_id TEXT
    CHECK (target_connection_id IS NULL OR length(target_connection_id) BETWEEN 1 AND 256);

-- +goose Down
ALTER TABLE mail_send_intents DROP COLUMN target_connection_id;
ALTER TABLE mail_send_intents DROP COLUMN target_provider_id;

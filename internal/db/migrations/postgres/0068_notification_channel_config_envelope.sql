-- +goose Up
-- +goose StatementBegin
-- Historical channel configuration remains explicit version zero. New rows
-- use a JSON envelope so the existing JSONB column keeps its type.
ALTER TABLE notification_channels ADD COLUMN config_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE notification_channels ADD COLUMN config_plaintext_bytes INTEGER;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channel_config_crypto_check CHECK (
    (config_crypto_version = 0 AND config_plaintext_bytes IS NULL)
    OR (config_crypto_version = 1 AND config_plaintext_bytes IS NOT NULL
        AND config_plaintext_bytes BETWEEN 0 AND 1048576
        AND jsonb_typeof(config_json) = 'object'
        AND config_json->>'__reactor_payload_envelope' LIKE 'reactor-payload:v1:%')
);
CREATE FUNCTION guard_notification_channel_config() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE plaintext_change BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        plaintext_change := NEW.config_crypto_version = 0;
    ELSE
        IF OLD.config_crypto_version = 1 AND NEW.config_crypto_version <> 1 THEN
            RAISE EXCEPTION 'encrypted notification config cannot become plaintext';
        END IF;
        plaintext_change := NEW.config_crypto_version = 0 AND
            (NEW.config_json IS DISTINCT FROM OLD.config_json
             OR NEW.config_crypto_version IS DISTINCT FROM OLD.config_crypto_version);
    END IF;
    IF plaintext_change THEN
        PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
        IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
            RAISE EXCEPTION 'journal payload key exists: encrypted notification config required';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER notification_channel_config_insert_guard BEFORE INSERT ON notification_channels
FOR EACH ROW EXECUTE FUNCTION guard_notification_channel_config();
CREATE TRIGGER notification_channel_config_update_guard
BEFORE UPDATE OF config_json, config_crypto_version, config_plaintext_bytes ON notification_channels
FOR EACH ROW EXECUTE FUNCTION guard_notification_channel_config();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1')
        OR EXISTS (SELECT 1 FROM notification_channels WHERE config_crypto_version = 1) THEN
        RAISE EXCEPTION 'cannot roll back notification encryption while encrypted rows or journal key exist';
    END IF;
END $$;
DROP TRIGGER notification_channel_config_update_guard ON notification_channels;
DROP TRIGGER notification_channel_config_insert_guard ON notification_channels;
DROP FUNCTION guard_notification_channel_config();
ALTER TABLE notification_channels DROP CONSTRAINT notification_channel_config_crypto_check;
ALTER TABLE notification_channels DROP COLUMN config_plaintext_bytes, DROP COLUMN config_crypto_version;
-- +goose StatementEnd

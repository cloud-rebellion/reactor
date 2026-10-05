-- +goose Up
-- +goose StatementBegin
ALTER TABLE notification_channels ADD COLUMN config_crypto_version INTEGER NOT NULL DEFAULT 0
    CHECK (config_crypto_version IN (0, 1));
ALTER TABLE notification_channels ADD COLUMN config_plaintext_bytes INTEGER
    CHECK (config_plaintext_bytes BETWEEN 0 AND 1048576);
CREATE TRIGGER notification_channel_config_insert_guard BEFORE INSERT ON notification_channels
WHEN (NEW.config_crypto_version = 0 AND NEW.config_plaintext_bytes IS NOT NULL)
    OR (NEW.config_crypto_version = 1 AND
        (NEW.config_plaintext_bytes IS NULL OR json_valid(NEW.config_json) = 0
         OR json_type(NEW.config_json, '$.__reactor_payload_envelope') <> 'text'
         OR json_extract(NEW.config_json, '$.__reactor_payload_envelope') NOT LIKE 'reactor-payload:v1:%'))
    OR (NEW.config_crypto_version = 0 AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted notification config required');
END;
CREATE TRIGGER notification_channel_config_update_guard
BEFORE UPDATE OF config_json, config_crypto_version, config_plaintext_bytes ON notification_channels
WHEN (OLD.config_crypto_version = 1 AND NEW.config_crypto_version <> 1)
    OR (NEW.config_crypto_version = 0 AND NEW.config_plaintext_bytes IS NOT NULL)
    OR (NEW.config_crypto_version = 1 AND
        (NEW.config_plaintext_bytes IS NULL OR json_valid(NEW.config_json) = 0
         OR json_type(NEW.config_json, '$.__reactor_payload_envelope') <> 'text'
         OR json_extract(NEW.config_json, '$.__reactor_payload_envelope') NOT LIKE 'reactor-payload:v1:%'))
    OR (NEW.config_crypto_version = 0
        AND (NEW.config_json IS NOT OLD.config_json OR NEW.config_crypto_version IS NOT OLD.config_crypto_version)
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted notification config required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_notification_config_down_guard (version INTEGER CHECK (version = 0));
INSERT INTO _reactor_notification_config_down_guard SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
INSERT INTO _reactor_notification_config_down_guard
    SELECT 1 FROM notification_channels WHERE config_crypto_version = 1 LIMIT 1;
DROP TABLE _reactor_notification_config_down_guard;
DROP TRIGGER notification_channel_config_update_guard;
DROP TRIGGER notification_channel_config_insert_guard;
ALTER TABLE notification_channels DROP COLUMN config_plaintext_bytes;
ALTER TABLE notification_channels DROP COLUMN config_crypto_version;
-- +goose StatementEnd

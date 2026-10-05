-- +goose Up
-- +goose StatementBegin
-- Existing definitions remain readable version zero until separately backfilled.
ALTER TABLE command_automation_versions ADD COLUMN definition_crypto_version INTEGER NOT NULL DEFAULT 0
    CHECK (definition_crypto_version IN (0, 1));
ALTER TABLE command_automation_versions ADD COLUMN definition_plaintext_bytes INTEGER
    CHECK (definition_plaintext_bytes BETWEEN 1 AND 131072);
ALTER TABLE command_automation_versions ADD COLUMN definition_sha256 TEXT;
CREATE TRIGGER command_definition_insert_guard BEFORE INSERT ON command_automation_versions
WHEN (NEW.definition_crypto_version = 0 AND
        (NEW.definition_plaintext_bytes IS NOT NULL OR NEW.definition_sha256 IS NOT NULL))
    OR (NEW.definition_crypto_version = 1 AND
        (NEW.definition_plaintext_bytes IS NULL OR NEW.definition_sha256 IS NULL
         OR length(NEW.definition_sha256) <> 64 OR NEW.definition_sha256 GLOB '*[^0-9a-f]*'
         OR json_valid(NEW.definition_json) = 0
         OR json_type(NEW.definition_json, '$.__reactor_payload_envelope') <> 'text'
         OR json_extract(NEW.definition_json, '$.__reactor_payload_envelope') NOT LIKE 'reactor-payload:v1:%'))
    OR (NEW.definition_crypto_version = 0 AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command definition required');
END;
CREATE TRIGGER command_definition_update_guard
BEFORE UPDATE OF definition_json, definition_crypto_version, definition_plaintext_bytes, definition_sha256 ON command_automation_versions
WHEN (OLD.definition_crypto_version = 1 AND NEW.definition_crypto_version <> 1)
    OR (NEW.definition_crypto_version = 0 AND
        (NEW.definition_plaintext_bytes IS NOT NULL OR NEW.definition_sha256 IS NOT NULL))
    OR (NEW.definition_crypto_version = 1 AND
        (NEW.definition_plaintext_bytes IS NULL OR NEW.definition_sha256 IS NULL
         OR length(NEW.definition_sha256) <> 64 OR NEW.definition_sha256 GLOB '*[^0-9a-f]*'
         OR json_valid(NEW.definition_json) = 0
         OR json_type(NEW.definition_json, '$.__reactor_payload_envelope') <> 'text'
         OR json_extract(NEW.definition_json, '$.__reactor_payload_envelope') NOT LIKE 'reactor-payload:v1:%'))
    OR (NEW.definition_crypto_version = 0
        AND (NEW.definition_json IS NOT OLD.definition_json OR NEW.definition_crypto_version IS NOT OLD.definition_crypto_version)
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command definition required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_command_definition_down_guard (version INTEGER CHECK (version = 0));
INSERT INTO _reactor_command_definition_down_guard SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
INSERT INTO _reactor_command_definition_down_guard
    SELECT 1 FROM command_automation_versions WHERE definition_crypto_version = 1 LIMIT 1;
DROP TABLE _reactor_command_definition_down_guard;
DROP TRIGGER command_definition_update_guard;
DROP TRIGGER command_definition_insert_guard;
ALTER TABLE command_automation_versions DROP COLUMN definition_sha256;
ALTER TABLE command_automation_versions DROP COLUMN definition_plaintext_bytes;
ALTER TABLE command_automation_versions DROP COLUMN definition_crypto_version;
-- +goose StatementEnd

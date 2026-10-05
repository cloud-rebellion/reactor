-- +goose Up
-- +goose StatementBegin
-- Historical rows remain explicit version zero. New keyed DLQ rows hold two
-- authenticated envelopes and their plaintext byte lengths.
ALTER TABLE dead_letter ADD COLUMN payload_crypto_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dead_letter ADD COLUMN error_plaintext_bytes INTEGER;
ALTER TABLE dead_letter ADD COLUMN payload_plaintext_bytes INTEGER;
CREATE TRIGGER dead_letter_payload_insert_guard
BEFORE INSERT ON dead_letter
WHEN (NEW.payload_crypto_version NOT IN (0, 1))
    OR (NEW.payload_crypto_version = 0 AND
        (NEW.error_plaintext_bytes IS NOT NULL OR NEW.payload_plaintext_bytes IS NOT NULL))
    OR (NEW.payload_crypto_version <> 1
      AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
    OR (NEW.payload_crypto_version = 1 AND
        (NEW.error_plaintext_bytes IS NULL OR NEW.error_plaintext_bytes NOT BETWEEN 0 AND 1048576
         OR NEW.payload_plaintext_bytes IS NULL OR NEW.payload_plaintext_bytes NOT BETWEEN 0 AND 1048576
         OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'
         OR NOT json_valid(NEW.payload)
         OR COALESCE(json_type(NEW.payload, '$.__reactor_payload_envelope'), '') <> 'text'
         OR substr(COALESCE(json_extract(NEW.payload, '$.__reactor_payload_envelope'), ''), 1, 19) <> 'reactor-payload:v1:'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted dead_letter required');
END;
CREATE TRIGGER dead_letter_payload_update_guard
BEFORE UPDATE OF error_text, payload, payload_crypto_version, error_plaintext_bytes, payload_plaintext_bytes ON dead_letter
WHEN (OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1)
    OR (NEW.payload_crypto_version NOT IN (0, 1))
    OR (NEW.payload_crypto_version = 0 AND
        (NEW.error_plaintext_bytes IS NOT NULL OR NEW.payload_plaintext_bytes IS NOT NULL))
    OR (NEW.payload_crypto_version <> 1
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
    OR (NEW.payload_crypto_version = 1 AND
        (NEW.error_plaintext_bytes IS NULL OR NEW.error_plaintext_bytes NOT BETWEEN 0 AND 1048576
         OR NEW.payload_plaintext_bytes IS NULL OR NEW.payload_plaintext_bytes NOT BETWEEN 0 AND 1048576
         OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'
         OR NOT json_valid(NEW.payload)
         OR COALESCE(json_type(NEW.payload, '$.__reactor_payload_envelope'), '') <> 'text'
         OR substr(COALESCE(json_extract(NEW.payload, '$.__reactor_payload_envelope'), ''), 1, 19) <> 'reactor-payload:v1:'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted dead_letter required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_dead_letter_payload_down_guard (
    version INTEGER CHECK (version = 0)
);
INSERT INTO _reactor_dead_letter_payload_down_guard (version)
    SELECT payload_crypto_version FROM dead_letter WHERE payload_crypto_version <> 0 LIMIT 1;
INSERT INTO _reactor_dead_letter_payload_down_guard (version)
    SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
DROP TABLE _reactor_dead_letter_payload_down_guard;
DROP TRIGGER dead_letter_payload_update_guard;
DROP TRIGGER dead_letter_payload_insert_guard;
ALTER TABLE dead_letter DROP COLUMN payload_crypto_version;
ALTER TABLE dead_letter DROP COLUMN error_plaintext_bytes;
ALTER TABLE dead_letter DROP COLUMN payload_plaintext_bytes;
-- +goose StatementEnd

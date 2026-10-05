-- +goose Up
-- +goose StatementBegin
ALTER TABLE steps ADD COLUMN payload_crypto_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE steps ADD COLUMN output_plaintext_bytes INTEGER;
ALTER TABLE steps ADD COLUMN error_plaintext_bytes INTEGER;
CREATE TRIGGER steps_payload_key_insert_guard
BEFORE INSERT ON steps
WHEN NEW.payload_crypto_version <> 1
    AND (NEW.output_jsonb IS NOT NULL OR NEW.error_text IS NOT NULL)
    AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1')
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted step required');
END;
CREATE TRIGGER steps_payload_key_update_guard
BEFORE UPDATE OF output_jsonb, error_text, payload_crypto_version ON steps
WHEN (OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1)
    OR (NEW.payload_crypto_version <> 1
        AND (NEW.output_jsonb IS NOT NULL OR NEW.error_text IS NOT NULL)
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted step required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_step_payload_down_guard (
    version INTEGER CHECK (version = 0)
);
INSERT INTO _reactor_step_payload_down_guard (version)
    SELECT payload_crypto_version FROM steps WHERE payload_crypto_version <> 0 LIMIT 1;
INSERT INTO _reactor_step_payload_down_guard (version)
    SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
DROP TABLE _reactor_step_payload_down_guard;
DROP TRIGGER steps_payload_key_update_guard;
DROP TRIGGER steps_payload_key_insert_guard;
ALTER TABLE steps DROP COLUMN payload_crypto_version;
ALTER TABLE steps DROP COLUMN output_plaintext_bytes;
ALTER TABLE steps DROP COLUMN error_plaintext_bytes;
-- +goose StatementEnd

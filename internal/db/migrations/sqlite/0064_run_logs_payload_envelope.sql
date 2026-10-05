-- +goose Up
-- +goose StatementBegin
ALTER TABLE run_logs ADD COLUMN payload_crypto_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE run_logs ADD COLUMN plaintext_bytes INTEGER;
ALTER TABLE run_logs ADD COLUMN kind TEXT NOT NULL DEFAULT 'runtime';
CREATE TRIGGER run_logs_payload_insert_guard
BEFORE INSERT ON run_logs
WHEN NEW.kind NOT IN ('runtime', 'artifact_fence')
    OR NEW.payload_crypto_version NOT IN (0, 1)
    OR (NEW.payload_crypto_version = 0 AND NEW.plaintext_bytes IS NOT NULL)
    OR (NEW.payload_crypto_version = 0
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
    OR (NEW.payload_crypto_version = 1 AND
        (NEW.plaintext_bytes IS NULL OR NEW.plaintext_bytes NOT BETWEEN 0 AND 8388608
         OR substr(NEW.line, 1, 19) <> 'reactor-payload:v1:'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted run log required');
END;
CREATE TRIGGER run_logs_payload_update_guard
BEFORE UPDATE OF line, payload_crypto_version, plaintext_bytes, kind ON run_logs
WHEN (OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1)
    OR NEW.kind NOT IN ('runtime', 'artifact_fence')
    OR NEW.payload_crypto_version NOT IN (0, 1)
    OR (NEW.payload_crypto_version = 0 AND NEW.plaintext_bytes IS NOT NULL)
    OR (NEW.payload_crypto_version = 0
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
    OR (NEW.payload_crypto_version = 1 AND
        (NEW.plaintext_bytes IS NULL OR NEW.plaintext_bytes NOT BETWEEN 0 AND 8388608
         OR substr(NEW.line, 1, 19) <> 'reactor-payload:v1:'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted run log required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_run_logs_payload_down_guard (
    version INTEGER CHECK (version = 0)
);
INSERT INTO _reactor_run_logs_payload_down_guard (version)
    SELECT payload_crypto_version FROM run_logs WHERE payload_crypto_version <> 0 LIMIT 1;
INSERT INTO _reactor_run_logs_payload_down_guard (version)
    SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
DROP TABLE _reactor_run_logs_payload_down_guard;
DROP TRIGGER run_logs_payload_update_guard;
DROP TRIGGER run_logs_payload_insert_guard;
ALTER TABLE run_logs DROP COLUMN kind;
ALTER TABLE run_logs DROP COLUMN plaintext_bytes;
ALTER TABLE run_logs DROP COLUMN payload_crypto_version;
-- +goose StatementEnd

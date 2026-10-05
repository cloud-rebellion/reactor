-- +goose Up
-- +goose StatementBegin
-- Historical rows remain explicit version zero. The kind preserves the
-- artifact-fence deduplication query after line contents are encrypted.
ALTER TABLE run_logs ADD COLUMN payload_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE run_logs ADD COLUMN plaintext_bytes BIGINT;
ALTER TABLE run_logs ADD COLUMN kind TEXT NOT NULL DEFAULT 'runtime';
ALTER TABLE run_logs ADD CONSTRAINT run_logs_payload_check CHECK (
    kind IN ('runtime', 'artifact_fence')
    AND (
        (payload_crypto_version = 0 AND plaintext_bytes IS NULL)
        OR (payload_crypto_version = 1
            AND plaintext_bytes IS NOT NULL
            AND plaintext_bytes BETWEEN 0 AND 8388608
            AND left(line, 19) = 'reactor-payload:v1:')
    )
);
CREATE FUNCTION guard_run_log_payload() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1 THEN
        RAISE EXCEPTION 'encrypted run log cannot become plaintext';
    END IF;
    IF NEW.payload_crypto_version = 1 THEN
        RETURN NEW;
    END IF;
    -- Share the first-key gate with run/step/DLQ writers. Ordinary encrypted
    -- writes do not contend here; a pre-key writer cannot commit after the key.
    PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'journal payload key exists: encrypted run log required';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER run_logs_payload_insert_guard
BEFORE INSERT ON run_logs FOR EACH ROW EXECUTE FUNCTION guard_run_log_payload();
CREATE TRIGGER run_logs_payload_update_guard
BEFORE UPDATE OF line, payload_crypto_version, plaintext_bytes, kind ON run_logs
FOR EACH ROW EXECUTE FUNCTION guard_run_log_payload();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM run_logs WHERE payload_crypto_version <> 0) THEN
        RAISE EXCEPTION 'cannot roll back run log encryption while encrypted rows exist';
    END IF;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'cannot roll back run log encryption while journal key is active';
    END IF;
END $$;
DROP TRIGGER run_logs_payload_update_guard ON run_logs;
DROP TRIGGER run_logs_payload_insert_guard ON run_logs;
DROP FUNCTION guard_run_log_payload();
ALTER TABLE run_logs DROP CONSTRAINT run_logs_payload_check;
ALTER TABLE run_logs DROP COLUMN kind;
ALTER TABLE run_logs DROP COLUMN plaintext_bytes;
ALTER TABLE run_logs DROP COLUMN payload_crypto_version;
-- +goose StatementEnd

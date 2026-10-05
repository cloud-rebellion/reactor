-- +goose Up
-- +goose StatementBegin
-- Historical signal rows stay explicit v0. New keyed rows keep only a
-- ciphertext token plus its indexed digest; delivery payloads are sealed in
-- the existing BYTEA column. The old token column remains for v0 replay.
ALTER TABLE schedules ADD COLUMN signal_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE schedules ADD COLUMN signal_token_ciphertext TEXT;
ALTER TABLE schedules ADD COLUMN signal_token_sha256 TEXT;
ALTER TABLE schedules ADD COLUMN signal_token_plaintext_bytes INTEGER;
ALTER TABLE schedules ADD COLUMN signal_payload_plaintext_bytes INTEGER;
CREATE UNIQUE INDEX schedules_signal_digest_seq_idx
    ON schedules(signal_token_sha256, seq) WHERE signal_token_sha256 IS NOT NULL;
ALTER TABLE schedules ADD CONSTRAINT schedules_signal_envelope_check CHECK (
    (signal_crypto_version = 0 AND signal_token_ciphertext IS NULL
        AND signal_token_sha256 IS NULL AND signal_token_plaintext_bytes IS NULL
        AND signal_payload_plaintext_bytes IS NULL)
    OR (kind = 'signal' AND signal_crypto_version = 1
        AND signal_token IS NULL AND signal_token_ciphertext IS NOT NULL
        AND left(signal_token_ciphertext, 19) = 'reactor-payload:v1:'
        AND octet_length(signal_token_ciphertext) <= 398
        AND signal_token_sha256 IS NOT NULL
        AND signal_token_sha256 ~ '^[0-9a-f]{64}$'
        AND signal_token_plaintext_bytes IS NOT NULL
        AND signal_token_plaintext_bytes BETWEEN 1 AND 256
        AND ((signal_payload IS NULL AND signal_payload_plaintext_bytes IS NULL)
             OR (signal_payload IS NOT NULL
                 AND signal_payload_plaintext_bytes IS NOT NULL
                 AND signal_payload_plaintext_bytes BETWEEN 1 AND 983040
                 AND octet_length(signal_payload) <= 1310777
                 AND substring(signal_payload from 1 for 19) =
                     convert_to('reactor-payload:v1:', 'UTF8'))))
);
CREATE FUNCTION guard_signal_payload() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.signal_crypto_version = 1
        AND NEW.signal_crypto_version <> 1 THEN
        RAISE EXCEPTION 'encrypted signal cannot become plaintext';
    END IF;
    IF NEW.kind = 'signal' AND NEW.signal_crypto_version = 0 THEN
        -- Serialize an old writer with first-key initialization.
        PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
        IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
            RAISE EXCEPTION 'journal payload key exists: encrypted signal required';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER schedules_signal_insert_guard
BEFORE INSERT ON schedules FOR EACH ROW EXECUTE FUNCTION guard_signal_payload();
CREATE TRIGGER schedules_signal_update_guard
BEFORE UPDATE OF kind, signal_token, signal_token_ciphertext, signal_token_sha256,
    signal_crypto_version, signal_token_plaintext_bytes, signal_payload,
    signal_payload_plaintext_bytes ON schedules
FOR EACH ROW EXECUTE FUNCTION guard_signal_payload();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM schedules WHERE signal_crypto_version <> 0) THEN
        RAISE EXCEPTION 'cannot roll back signal encryption while encrypted rows exist';
    END IF;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'cannot roll back signal encryption while journal key is active';
    END IF;
END $$;
DROP TRIGGER schedules_signal_update_guard ON schedules;
DROP TRIGGER schedules_signal_insert_guard ON schedules;
DROP FUNCTION guard_signal_payload();
ALTER TABLE schedules DROP CONSTRAINT schedules_signal_envelope_check;
DROP INDEX schedules_signal_digest_seq_idx;
ALTER TABLE schedules DROP COLUMN signal_payload_plaintext_bytes;
ALTER TABLE schedules DROP COLUMN signal_token_plaintext_bytes;
ALTER TABLE schedules DROP COLUMN signal_token_sha256;
ALTER TABLE schedules DROP COLUMN signal_token_ciphertext;
ALTER TABLE schedules DROP COLUMN signal_crypto_version;
-- +goose StatementEnd

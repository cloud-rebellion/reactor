-- +goose Up
-- +goose StatementBegin
ALTER TABLE schedules ADD COLUMN signal_crypto_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE schedules ADD COLUMN signal_token_ciphertext TEXT;
ALTER TABLE schedules ADD COLUMN signal_token_sha256 TEXT;
ALTER TABLE schedules ADD COLUMN signal_token_plaintext_bytes INTEGER;
ALTER TABLE schedules ADD COLUMN signal_payload_plaintext_bytes INTEGER;
CREATE UNIQUE INDEX schedules_signal_digest_seq_idx
    ON schedules(signal_token_sha256, seq) WHERE signal_token_sha256 IS NOT NULL;
CREATE TRIGGER schedules_signal_insert_guard BEFORE INSERT ON schedules
WHEN (NEW.signal_crypto_version = 0 AND
        (NEW.signal_token_ciphertext IS NOT NULL OR NEW.signal_token_sha256 IS NOT NULL
         OR NEW.signal_token_plaintext_bytes IS NOT NULL OR NEW.signal_payload_plaintext_bytes IS NOT NULL
         OR (NEW.kind = 'signal' AND EXISTS
             (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))))
    OR (NEW.signal_crypto_version = 1 AND
        (NEW.kind <> 'signal' OR NEW.signal_token IS NOT NULL
         OR NEW.signal_token_ciphertext IS NULL
         OR substr(NEW.signal_token_ciphertext, 1, 19) <> 'reactor-payload:v1:'
         OR length(CAST(NEW.signal_token_ciphertext AS BLOB)) > 398
         OR NEW.signal_token_sha256 IS NULL OR length(NEW.signal_token_sha256) <> 64
         OR NEW.signal_token_sha256 GLOB '*[^0-9a-f]*'
         OR NEW.signal_token_plaintext_bytes IS NULL
         OR NEW.signal_token_plaintext_bytes NOT BETWEEN 1 AND 256
         OR (NEW.signal_payload IS NULL AND NEW.signal_payload_plaintext_bytes IS NOT NULL)
         OR (NEW.signal_payload IS NOT NULL AND
             (NEW.signal_payload_plaintext_bytes IS NULL
              OR NEW.signal_payload_plaintext_bytes NOT BETWEEN 1 AND 983040
              OR length(CAST(NEW.signal_payload AS BLOB)) > 1310777
              OR substr(CAST(NEW.signal_payload AS TEXT), 1, 19) <> 'reactor-payload:v1:'))))
    OR NEW.signal_crypto_version NOT IN (0, 1)
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted signal required');
END;
CREATE TRIGGER schedules_signal_update_guard
BEFORE UPDATE OF kind, signal_token, signal_token_ciphertext, signal_token_sha256,
    signal_crypto_version, signal_token_plaintext_bytes, signal_payload,
    signal_payload_plaintext_bytes ON schedules
WHEN (OLD.signal_crypto_version = 1 AND NEW.signal_crypto_version <> 1)
    OR (NEW.signal_crypto_version = 0 AND
        (NEW.signal_token_ciphertext IS NOT NULL OR NEW.signal_token_sha256 IS NOT NULL
         OR NEW.signal_token_plaintext_bytes IS NOT NULL OR NEW.signal_payload_plaintext_bytes IS NOT NULL
         OR (NEW.kind = 'signal' AND EXISTS
             (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))))
    OR (NEW.signal_crypto_version = 1 AND
        (NEW.kind <> 'signal' OR NEW.signal_token IS NOT NULL
         OR NEW.signal_token_ciphertext IS NULL
         OR substr(NEW.signal_token_ciphertext, 1, 19) <> 'reactor-payload:v1:'
         OR length(CAST(NEW.signal_token_ciphertext AS BLOB)) > 398
         OR NEW.signal_token_sha256 IS NULL OR length(NEW.signal_token_sha256) <> 64
         OR NEW.signal_token_sha256 GLOB '*[^0-9a-f]*'
         OR NEW.signal_token_plaintext_bytes IS NULL
         OR NEW.signal_token_plaintext_bytes NOT BETWEEN 1 AND 256
         OR (NEW.signal_payload IS NULL AND NEW.signal_payload_plaintext_bytes IS NOT NULL)
         OR (NEW.signal_payload IS NOT NULL AND
             (NEW.signal_payload_plaintext_bytes IS NULL
              OR NEW.signal_payload_plaintext_bytes NOT BETWEEN 1 AND 983040
              OR length(CAST(NEW.signal_payload AS BLOB)) > 1310777
              OR substr(CAST(NEW.signal_payload AS TEXT), 1, 19) <> 'reactor-payload:v1:'))))
    OR NEW.signal_crypto_version NOT IN (0, 1)
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted signal required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_signal_payload_down_guard (
    version INTEGER CHECK (version = 0)
);
INSERT INTO _reactor_signal_payload_down_guard (version)
    SELECT signal_crypto_version FROM schedules WHERE signal_crypto_version <> 0 LIMIT 1;
INSERT INTO _reactor_signal_payload_down_guard (version)
    SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
DROP TABLE _reactor_signal_payload_down_guard;
DROP TRIGGER schedules_signal_update_guard;
DROP TRIGGER schedules_signal_insert_guard;
DROP INDEX schedules_signal_digest_seq_idx;
ALTER TABLE schedules DROP COLUMN signal_payload_plaintext_bytes;
ALTER TABLE schedules DROP COLUMN signal_token_plaintext_bytes;
ALTER TABLE schedules DROP COLUMN signal_token_sha256;
ALTER TABLE schedules DROP COLUMN signal_token_ciphertext;
ALTER TABLE schedules DROP COLUMN signal_crypto_version;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin
-- Version zero is an explicit historical plaintext row. New keyed journal
-- writers seal both trigger_meta and trigger_input and set version one in the
-- same INSERT. A v1 reader refuses missing, swapped, or corrupt envelopes.
ALTER TABLE runs ADD COLUMN payload_crypto_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN payload_plaintext_bytes INTEGER;
CREATE TABLE journal_payload_keys (
    id          TEXT PRIMARY KEY CHECK (id = 'v1'),
    wrapped_key BLOB NOT NULL
);
CREATE TRIGGER runs_payload_key_insert_guard
BEFORE INSERT ON runs
WHEN NEW.payload_crypto_version <> 1
 AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1')
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted run required');
END;
CREATE TRIGGER runs_payload_version_update_guard
BEFORE UPDATE OF payload_crypto_version ON runs
WHEN OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1
BEGIN
    SELECT RAISE(ABORT, 'encrypted run cannot become plaintext');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_payload_down_guard (
    version INTEGER CHECK (version = 0)
);
INSERT INTO _reactor_payload_down_guard (version)
    SELECT payload_crypto_version FROM runs WHERE payload_crypto_version <> 0 LIMIT 1;
DROP TABLE _reactor_payload_down_guard;
DROP TRIGGER runs_payload_version_update_guard;
DROP TRIGGER runs_payload_key_insert_guard;
ALTER TABLE runs DROP COLUMN payload_crypto_version;
ALTER TABLE runs DROP COLUMN payload_plaintext_bytes;
DROP TABLE journal_payload_keys;
-- +goose StatementEnd

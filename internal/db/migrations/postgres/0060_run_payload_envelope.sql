-- +goose Up
-- +goose StatementBegin
-- Version zero is an explicit historical plaintext row. New keyed journal
-- writers seal both trigger_meta and trigger_input and set version one in the
-- same INSERT. A v1 reader refuses missing, swapped, or corrupt envelopes.
ALTER TABLE runs ADD COLUMN payload_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN payload_plaintext_bytes BIGINT;
CREATE TABLE journal_payload_keys (
    id          TEXT PRIMARY KEY CHECK (id = 'v1'),
    wrapped_key BYTEA NOT NULL
);
CREATE TABLE journal_payload_gate (
    id TEXT PRIMARY KEY CHECK (id = 'v1')
);
INSERT INTO journal_payload_gate (id) VALUES ('v1');
CREATE FUNCTION guard_run_payload_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- The key-initialization transaction takes FOR UPDATE on this row.
    -- This share lock makes an old writer commit before initialization or
    -- observe the committed key and fail, never race a late plaintext INSERT.
    PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
    IF NEW.payload_crypto_version <> 1
       AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'journal payload key exists: encrypted run required';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER runs_payload_key_insert_guard
BEFORE INSERT ON runs FOR EACH ROW EXECUTE FUNCTION guard_run_payload_insert();
CREATE FUNCTION guard_run_payload_version_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1 THEN
        RAISE EXCEPTION 'encrypted run cannot become plaintext';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER runs_payload_version_update_guard
BEFORE UPDATE OF payload_crypto_version ON runs FOR EACH ROW
EXECUTE FUNCTION guard_run_payload_version_update();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM runs WHERE payload_crypto_version <> 0) THEN
        RAISE EXCEPTION 'cannot roll back run payload encryption while encrypted rows exist';
    END IF;
END $$;
DROP TRIGGER runs_payload_version_update_guard ON runs;
DROP FUNCTION guard_run_payload_version_update();
DROP TRIGGER runs_payload_key_insert_guard ON runs;
DROP FUNCTION guard_run_payload_insert();
ALTER TABLE runs DROP COLUMN payload_crypto_version;
ALTER TABLE runs DROP COLUMN payload_plaintext_bytes;
DROP TABLE journal_payload_gate;
DROP TABLE journal_payload_keys;
-- +goose StatementEnd

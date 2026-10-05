-- +goose Up
-- +goose StatementBegin
-- Historical rows stay explicit version zero. A completed keyed attempt stores
-- output and error envelopes with their authenticated plaintext byte lengths.
ALTER TABLE steps ADD COLUMN payload_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE steps ADD COLUMN output_plaintext_bytes BIGINT;
ALTER TABLE steps ADD COLUMN error_plaintext_bytes BIGINT;
ALTER TABLE steps ADD CONSTRAINT steps_payload_crypto_version_check CHECK (payload_crypto_version IN (0, 1));
ALTER TABLE steps ADD CONSTRAINT steps_payload_lengths_check CHECK (
    (payload_crypto_version = 0 AND output_plaintext_bytes IS NULL AND error_plaintext_bytes IS NULL)
    OR (payload_crypto_version = 1
        AND (output_jsonb IS NULL) = (output_plaintext_bytes IS NULL)
        AND (error_text IS NULL) = (error_plaintext_bytes IS NULL)
        AND (output_plaintext_bytes IS NULL OR output_plaintext_bytes >= 0)
        AND (error_plaintext_bytes IS NULL OR error_plaintext_bytes >= 0))
);
CREATE FUNCTION guard_step_payload_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.payload_crypto_version = 1
       OR (NEW.output_jsonb IS NULL AND NEW.error_text IS NULL) THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'journal payload key exists: encrypted step required';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER steps_payload_key_insert_guard
BEFORE INSERT ON steps FOR EACH ROW EXECUTE FUNCTION guard_step_payload_insert();
CREATE FUNCTION guard_step_payload_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1 THEN
        RAISE EXCEPTION 'encrypted step cannot become plaintext';
    END IF;
    IF NEW.payload_crypto_version = 1
       OR (NEW.output_jsonb IS NULL AND NEW.error_text IS NULL) THEN
        RETURN NEW;
    END IF;
    -- Share the gate that serializes first key initialization only for a
    -- plaintext outcome. Normal encrypted writes do not contend on it.
    PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'journal payload key exists: encrypted step required';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER steps_payload_key_update_guard
BEFORE UPDATE OF output_jsonb, error_text, payload_crypto_version ON steps
FOR EACH ROW EXECUTE FUNCTION guard_step_payload_update();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM steps WHERE payload_crypto_version <> 0) THEN
        RAISE EXCEPTION 'cannot roll back step payload encryption while encrypted rows exist';
    END IF;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'cannot roll back step payload encryption while journal key is active';
    END IF;
END $$;
DROP TRIGGER steps_payload_key_update_guard ON steps;
DROP FUNCTION guard_step_payload_update();
DROP TRIGGER steps_payload_key_insert_guard ON steps;
DROP FUNCTION guard_step_payload_insert();
ALTER TABLE steps DROP CONSTRAINT steps_payload_lengths_check;
ALTER TABLE steps DROP CONSTRAINT steps_payload_crypto_version_check;
ALTER TABLE steps DROP COLUMN payload_crypto_version;
ALTER TABLE steps DROP COLUMN output_plaintext_bytes;
ALTER TABLE steps DROP COLUMN error_plaintext_bytes;
-- +goose StatementEnd

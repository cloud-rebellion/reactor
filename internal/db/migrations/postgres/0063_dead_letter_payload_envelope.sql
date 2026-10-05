-- +goose Up
-- +goose StatementBegin
-- Historical rows remain explicit version zero. New keyed DLQ rows hold two
-- authenticated envelopes and their plaintext byte lengths.
ALTER TABLE dead_letter ADD COLUMN payload_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE dead_letter ADD COLUMN error_plaintext_bytes BIGINT;
ALTER TABLE dead_letter ADD COLUMN payload_plaintext_bytes BIGINT;
ALTER TABLE dead_letter ADD CONSTRAINT dead_letter_payload_crypto_check CHECK (
    (payload_crypto_version = 0 AND error_plaintext_bytes IS NULL AND payload_plaintext_bytes IS NULL)
    OR (payload_crypto_version = 1
        AND error_plaintext_bytes IS NOT NULL AND payload_plaintext_bytes IS NOT NULL
        AND error_plaintext_bytes BETWEEN 0 AND 1048576
        AND payload_plaintext_bytes BETWEEN 0 AND 1048576
        AND left(error_text, 19) = 'reactor-payload:v1:'
        AND jsonb_typeof(payload) = 'object'
        AND payload ? '__reactor_payload_envelope'
        AND jsonb_typeof(payload->'__reactor_payload_envelope') = 'string'
        AND left(payload->>'__reactor_payload_envelope', 19) = 'reactor-payload:v1:')
);
CREATE FUNCTION guard_dead_letter_payload() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.payload_crypto_version = 1 AND NEW.payload_crypto_version <> 1 THEN
        RAISE EXCEPTION 'encrypted dead_letter cannot become plaintext';
    END IF;
    IF NEW.payload_crypto_version = 1 THEN
        RETURN NEW;
    END IF;
    -- Serialize a pre-key old writer with first-key initialization. Ordinary
    -- encrypted writes do not contend on this gate.
    PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'journal payload key exists: encrypted dead_letter required';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER dead_letter_payload_insert_guard
BEFORE INSERT ON dead_letter FOR EACH ROW EXECUTE FUNCTION guard_dead_letter_payload();
CREATE TRIGGER dead_letter_payload_update_guard
BEFORE UPDATE OF error_text, payload, payload_crypto_version, error_plaintext_bytes, payload_plaintext_bytes ON dead_letter
FOR EACH ROW EXECUTE FUNCTION guard_dead_letter_payload();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM dead_letter WHERE payload_crypto_version <> 0) THEN
        RAISE EXCEPTION 'cannot roll back dead_letter payload encryption while encrypted rows exist';
    END IF;
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
        RAISE EXCEPTION 'cannot roll back dead_letter payload encryption while journal key is active';
    END IF;
END $$;
DROP TRIGGER dead_letter_payload_update_guard ON dead_letter;
DROP TRIGGER dead_letter_payload_insert_guard ON dead_letter;
DROP FUNCTION guard_dead_letter_payload();
ALTER TABLE dead_letter DROP CONSTRAINT dead_letter_payload_crypto_check;
ALTER TABLE dead_letter DROP COLUMN payload_crypto_version;
ALTER TABLE dead_letter DROP COLUMN error_plaintext_bytes;
ALTER TABLE dead_letter DROP COLUMN payload_plaintext_bytes;
-- +goose StatementEnd

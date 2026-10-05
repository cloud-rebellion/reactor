-- +goose Up
-- +goose StatementBegin
-- Historical definitions remain explicit version zero until a separate backfill.
-- New keyed definitions use a JSON envelope to preserve the JSONB column type.
ALTER TABLE command_automation_versions ADD COLUMN definition_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_automation_versions ADD COLUMN definition_plaintext_bytes INTEGER;
ALTER TABLE command_automation_versions ADD COLUMN definition_sha256 TEXT;
ALTER TABLE command_automation_versions ADD CONSTRAINT command_definition_crypto_check CHECK (
    (definition_crypto_version = 0 AND definition_plaintext_bytes IS NULL AND definition_sha256 IS NULL)
    OR (definition_crypto_version = 1 AND definition_plaintext_bytes IS NOT NULL
        AND definition_plaintext_bytes BETWEEN 1 AND 131072
        AND definition_sha256 IS NOT NULL AND definition_sha256 ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(definition_json) = 'object'
        AND definition_json ? '__reactor_payload_envelope'
        AND definition_json->>'__reactor_payload_envelope' LIKE 'reactor-payload:v1:%')
);
CREATE FUNCTION guard_command_definition_envelope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE plaintext_change BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        plaintext_change := NEW.definition_crypto_version = 0;
    ELSE
        IF OLD.definition_crypto_version = 1 AND NEW.definition_crypto_version <> 1 THEN
            RAISE EXCEPTION 'encrypted command definition cannot become plaintext';
        END IF;
        plaintext_change := NEW.definition_crypto_version = 0 AND
            (NEW.definition_json IS DISTINCT FROM OLD.definition_json
             OR NEW.definition_crypto_version IS DISTINCT FROM OLD.definition_crypto_version);
    END IF;
    IF plaintext_change THEN
        PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
        IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
            RAISE EXCEPTION 'journal payload key exists: encrypted command definition required';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER command_definition_insert_guard BEFORE INSERT ON command_automation_versions
FOR EACH ROW EXECUTE FUNCTION guard_command_definition_envelope();
CREATE TRIGGER command_definition_update_guard
BEFORE UPDATE OF definition_json, definition_crypto_version, definition_plaintext_bytes, definition_sha256 ON command_automation_versions
FOR EACH ROW EXECUTE FUNCTION guard_command_definition_envelope();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1')
        OR EXISTS (SELECT 1 FROM command_automation_versions WHERE definition_crypto_version = 1) THEN
        RAISE EXCEPTION 'cannot roll back command definition encryption while encrypted rows or journal key exist';
    END IF;
END $$;
DROP TRIGGER command_definition_update_guard ON command_automation_versions;
DROP TRIGGER command_definition_insert_guard ON command_automation_versions;
DROP FUNCTION guard_command_definition_envelope();
ALTER TABLE command_automation_versions DROP CONSTRAINT command_definition_crypto_check;
ALTER TABLE command_automation_versions DROP COLUMN definition_sha256, DROP COLUMN definition_plaintext_bytes, DROP COLUMN definition_crypto_version;
-- +goose StatementEnd

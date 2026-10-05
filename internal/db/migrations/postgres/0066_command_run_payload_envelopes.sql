-- +goose Up
-- +goose StatementBegin
-- Historical command-run fields remain explicit version zero. Separate field
-- versions let a crash/recovery error be sealed without rewriting live output.
ALTER TABLE command_runs ADD COLUMN error_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_runs ADD COLUMN error_plaintext_bytes INTEGER;
ALTER TABLE command_run_steps ADD COLUMN stdout_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_run_steps ADD COLUMN stderr_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_run_steps ADD COLUMN error_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_run_steps ADD COLUMN error_plaintext_bytes INTEGER;
ALTER TABLE command_run_step_attempts ADD COLUMN stdout_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_run_step_attempts ADD COLUMN stderr_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_run_step_attempts ADD COLUMN error_crypto_version SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE command_run_step_attempts ADD COLUMN error_plaintext_bytes INTEGER;
ALTER TABLE command_runs ADD CONSTRAINT command_runs_error_crypto_check CHECK (
    (error_crypto_version = 0 AND error_plaintext_bytes IS NULL)
    OR (error_crypto_version = 1 AND error_text IS NOT NULL
        AND error_plaintext_bytes IS NOT NULL AND error_plaintext_bytes BETWEEN 0 AND 16384
        AND left(error_text, 19) = 'reactor-payload:v1:')
);
ALTER TABLE command_run_steps ADD CONSTRAINT command_run_steps_crypto_check CHECK (
    stdout_crypto_version IN (0, 1) AND stderr_crypto_version IN (0, 1)
    AND ((stdout_crypto_version = 0) OR left(stdout_text, 19) = 'reactor-payload:v1:')
    AND ((stderr_crypto_version = 0) OR left(stderr_text, 19) = 'reactor-payload:v1:')
    AND ((error_crypto_version = 0 AND error_plaintext_bytes IS NULL)
        OR (error_crypto_version = 1 AND error_plaintext_bytes IS NOT NULL AND error_plaintext_bytes BETWEEN 0 AND 16384
            AND left(error_text, 19) = 'reactor-payload:v1:'))
);
ALTER TABLE command_run_step_attempts ADD CONSTRAINT command_run_step_attempts_crypto_check CHECK (
    stdout_crypto_version IN (0, 1) AND stderr_crypto_version IN (0, 1)
    AND ((stdout_crypto_version = 0) OR left(stdout_text, 19) = 'reactor-payload:v1:')
    AND ((stderr_crypto_version = 0) OR left(stderr_text, 19) = 'reactor-payload:v1:')
    AND ((error_crypto_version = 0 AND error_plaintext_bytes IS NULL)
        OR (error_crypto_version = 1 AND error_plaintext_bytes IS NOT NULL AND error_plaintext_bytes BETWEEN 0 AND 16384
            AND left(error_text, 19) = 'reactor-payload:v1:'))
);
CREATE FUNCTION guard_command_execution_payload() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE needs_plaintext_guard BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'INSERT' THEN
        needs_plaintext_guard := NEW.error_crypto_version = 0 AND COALESCE(NEW.error_text, '') <> '';
        IF TG_TABLE_NAME <> 'command_runs' THEN
            needs_plaintext_guard := needs_plaintext_guard
                OR (NEW.stdout_crypto_version = 0 AND NEW.stdout_text <> '')
                OR (NEW.stderr_crypto_version = 0 AND NEW.stderr_text <> '');
        END IF;
    ELSE
        IF OLD.error_crypto_version = 1 AND NEW.error_crypto_version <> 1 THEN
            RAISE EXCEPTION 'encrypted command error cannot become plaintext';
        END IF;
        IF TG_TABLE_NAME <> 'command_runs' THEN
            IF OLD.stdout_crypto_version = 1 AND NEW.stdout_crypto_version <> 1 THEN
                RAISE EXCEPTION 'encrypted command stdout cannot become plaintext';
            END IF;
            IF OLD.stderr_crypto_version = 1 AND NEW.stderr_crypto_version <> 1 THEN
                RAISE EXCEPTION 'encrypted command stderr cannot become plaintext';
            END IF;
        END IF;
        IF NEW.error_crypto_version = 0 AND COALESCE(NEW.error_text, '') <> ''
            AND (NEW.error_text IS DISTINCT FROM OLD.error_text
                 OR NEW.error_crypto_version IS DISTINCT FROM OLD.error_crypto_version) THEN
            needs_plaintext_guard := TRUE;
        END IF;
        IF TG_TABLE_NAME <> 'command_runs' THEN
            IF NEW.stdout_crypto_version = 0 AND NEW.stdout_text <> ''
                AND (NEW.stdout_text IS DISTINCT FROM OLD.stdout_text
                     OR NEW.stdout_crypto_version IS DISTINCT FROM OLD.stdout_crypto_version) THEN
                needs_plaintext_guard := TRUE;
            END IF;
            IF NEW.stderr_crypto_version = 0 AND NEW.stderr_text <> ''
                AND (NEW.stderr_text IS DISTINCT FROM OLD.stderr_text
                     OR NEW.stderr_crypto_version IS DISTINCT FROM OLD.stderr_crypto_version) THEN
                needs_plaintext_guard := TRUE;
            END IF;
        END IF;
    END IF;
    IF needs_plaintext_guard THEN
        PERFORM 1 FROM journal_payload_gate WHERE id = 'v1' FOR SHARE;
        IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') THEN
            RAISE EXCEPTION 'journal payload key exists: encrypted command output required';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER command_runs_payload_insert_guard BEFORE INSERT ON command_runs
FOR EACH ROW EXECUTE FUNCTION guard_command_execution_payload();
CREATE TRIGGER command_runs_payload_update_guard
BEFORE UPDATE OF error_text, error_crypto_version, error_plaintext_bytes ON command_runs
FOR EACH ROW EXECUTE FUNCTION guard_command_execution_payload();
CREATE TRIGGER command_run_steps_payload_insert_guard BEFORE INSERT ON command_run_steps
FOR EACH ROW EXECUTE FUNCTION guard_command_execution_payload();
CREATE TRIGGER command_run_steps_payload_update_guard
BEFORE UPDATE OF stdout_text, stderr_text, error_text, stdout_crypto_version, stderr_crypto_version,
    error_crypto_version, error_plaintext_bytes ON command_run_steps
FOR EACH ROW EXECUTE FUNCTION guard_command_execution_payload();
CREATE TRIGGER command_run_step_attempts_payload_insert_guard BEFORE INSERT ON command_run_step_attempts
FOR EACH ROW EXECUTE FUNCTION guard_command_execution_payload();
CREATE TRIGGER command_run_step_attempts_payload_update_guard
BEFORE UPDATE OF stdout_text, stderr_text, error_text, stdout_crypto_version, stderr_crypto_version,
    error_crypto_version, error_plaintext_bytes ON command_run_step_attempts
FOR EACH ROW EXECUTE FUNCTION guard_command_execution_payload();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1')
        OR EXISTS (SELECT 1 FROM command_runs WHERE error_crypto_version = 1)
        OR EXISTS (SELECT 1 FROM command_run_steps WHERE stdout_crypto_version = 1 OR stderr_crypto_version = 1 OR error_crypto_version = 1)
        OR EXISTS (SELECT 1 FROM command_run_step_attempts WHERE stdout_crypto_version = 1 OR stderr_crypto_version = 1 OR error_crypto_version = 1) THEN
        RAISE EXCEPTION 'cannot roll back command execution encryption while encrypted rows or journal key exist';
    END IF;
END $$;
DROP TRIGGER command_run_step_attempts_payload_update_guard ON command_run_step_attempts;
DROP TRIGGER command_run_step_attempts_payload_insert_guard ON command_run_step_attempts;
DROP TRIGGER command_run_steps_payload_update_guard ON command_run_steps;
DROP TRIGGER command_run_steps_payload_insert_guard ON command_run_steps;
DROP TRIGGER command_runs_payload_update_guard ON command_runs;
DROP TRIGGER command_runs_payload_insert_guard ON command_runs;
DROP FUNCTION guard_command_execution_payload();
ALTER TABLE command_run_step_attempts DROP CONSTRAINT command_run_step_attempts_crypto_check;
ALTER TABLE command_run_steps DROP CONSTRAINT command_run_steps_crypto_check;
ALTER TABLE command_runs DROP CONSTRAINT command_runs_error_crypto_check;
ALTER TABLE command_run_step_attempts DROP COLUMN error_plaintext_bytes, DROP COLUMN error_crypto_version,
    DROP COLUMN stderr_crypto_version, DROP COLUMN stdout_crypto_version;
ALTER TABLE command_run_steps DROP COLUMN error_plaintext_bytes, DROP COLUMN error_crypto_version,
    DROP COLUMN stderr_crypto_version, DROP COLUMN stdout_crypto_version;
ALTER TABLE command_runs DROP COLUMN error_plaintext_bytes, DROP COLUMN error_crypto_version;
-- +goose StatementEnd

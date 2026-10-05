-- +goose Up
-- +goose StatementBegin
ALTER TABLE command_runs ADD COLUMN error_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (error_crypto_version IN (0, 1));
ALTER TABLE command_runs ADD COLUMN error_plaintext_bytes INTEGER CHECK (error_plaintext_bytes BETWEEN 0 AND 16384);
ALTER TABLE command_run_steps ADD COLUMN stdout_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (stdout_crypto_version IN (0, 1));
ALTER TABLE command_run_steps ADD COLUMN stderr_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (stderr_crypto_version IN (0, 1));
ALTER TABLE command_run_steps ADD COLUMN error_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (error_crypto_version IN (0, 1));
ALTER TABLE command_run_steps ADD COLUMN error_plaintext_bytes INTEGER CHECK (error_plaintext_bytes BETWEEN 0 AND 16384);
ALTER TABLE command_run_step_attempts ADD COLUMN stdout_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (stdout_crypto_version IN (0, 1));
ALTER TABLE command_run_step_attempts ADD COLUMN stderr_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (stderr_crypto_version IN (0, 1));
ALTER TABLE command_run_step_attempts ADD COLUMN error_crypto_version INTEGER NOT NULL DEFAULT 0 CHECK (error_crypto_version IN (0, 1));
ALTER TABLE command_run_step_attempts ADD COLUMN error_plaintext_bytes INTEGER CHECK (error_plaintext_bytes BETWEEN 0 AND 16384);

CREATE TRIGGER command_runs_payload_insert_guard BEFORE INSERT ON command_runs
WHEN (NEW.error_crypto_version = 0 AND NEW.error_plaintext_bytes IS NOT NULL)
    OR (NEW.error_crypto_version = 1 AND
        (NEW.error_text IS NULL OR NEW.error_plaintext_bytes IS NULL
         OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'))
    OR (NEW.error_crypto_version = 0 AND COALESCE(NEW.error_text, '') <> ''
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command output required');
END;
CREATE TRIGGER command_runs_payload_update_guard
BEFORE UPDATE OF error_text, error_crypto_version, error_plaintext_bytes ON command_runs
WHEN (OLD.error_crypto_version = 1 AND NEW.error_crypto_version <> 1)
    OR (NEW.error_crypto_version = 0 AND NEW.error_plaintext_bytes IS NOT NULL)
    OR (NEW.error_crypto_version = 1 AND
        (NEW.error_text IS NULL OR NEW.error_plaintext_bytes IS NULL
         OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'))
    OR (NEW.error_crypto_version = 0 AND COALESCE(NEW.error_text, '') <> ''
        AND (NEW.error_text IS NOT OLD.error_text OR NEW.error_crypto_version IS NOT OLD.error_crypto_version)
        AND EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1'))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command output required');
END;

CREATE TRIGGER command_run_steps_payload_insert_guard BEFORE INSERT ON command_run_steps
WHEN (NEW.stdout_crypto_version = 1 AND substr(NEW.stdout_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.stderr_crypto_version = 1 AND substr(NEW.stderr_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.error_crypto_version = 0 AND NEW.error_plaintext_bytes IS NOT NULL)
    OR (NEW.error_crypto_version = 1 AND
        (NEW.error_plaintext_bytes IS NULL OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'))
    OR (EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') AND (
        (NEW.stdout_crypto_version = 0 AND NEW.stdout_text <> '')
        OR (NEW.stderr_crypto_version = 0 AND NEW.stderr_text <> '')
        OR (NEW.error_crypto_version = 0 AND NEW.error_text <> '')))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command output required');
END;
CREATE TRIGGER command_run_steps_payload_update_guard
BEFORE UPDATE OF stdout_text, stderr_text, error_text, stdout_crypto_version, stderr_crypto_version,
    error_crypto_version, error_plaintext_bytes ON command_run_steps
WHEN (OLD.stdout_crypto_version = 1 AND NEW.stdout_crypto_version <> 1)
    OR (OLD.stderr_crypto_version = 1 AND NEW.stderr_crypto_version <> 1)
    OR (OLD.error_crypto_version = 1 AND NEW.error_crypto_version <> 1)
    OR (NEW.stdout_crypto_version = 1 AND substr(NEW.stdout_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.stderr_crypto_version = 1 AND substr(NEW.stderr_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.error_crypto_version = 0 AND NEW.error_plaintext_bytes IS NOT NULL)
    OR (NEW.error_crypto_version = 1 AND
        (NEW.error_plaintext_bytes IS NULL OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'))
    OR (EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') AND (
        (NEW.stdout_crypto_version = 0 AND NEW.stdout_text <> ''
            AND (NEW.stdout_text IS NOT OLD.stdout_text OR NEW.stdout_crypto_version IS NOT OLD.stdout_crypto_version))
        OR (NEW.stderr_crypto_version = 0 AND NEW.stderr_text <> ''
            AND (NEW.stderr_text IS NOT OLD.stderr_text OR NEW.stderr_crypto_version IS NOT OLD.stderr_crypto_version))
        OR (NEW.error_crypto_version = 0 AND NEW.error_text <> ''
            AND (NEW.error_text IS NOT OLD.error_text OR NEW.error_crypto_version IS NOT OLD.error_crypto_version))))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command output required');
END;

CREATE TRIGGER command_run_step_attempts_payload_insert_guard BEFORE INSERT ON command_run_step_attempts
WHEN (NEW.stdout_crypto_version = 1 AND substr(NEW.stdout_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.stderr_crypto_version = 1 AND substr(NEW.stderr_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.error_crypto_version = 0 AND NEW.error_plaintext_bytes IS NOT NULL)
    OR (NEW.error_crypto_version = 1 AND
        (NEW.error_plaintext_bytes IS NULL OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'))
    OR (EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') AND (
        (NEW.stdout_crypto_version = 0 AND NEW.stdout_text <> '')
        OR (NEW.stderr_crypto_version = 0 AND NEW.stderr_text <> '')
        OR (NEW.error_crypto_version = 0 AND NEW.error_text <> '')))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command output required');
END;
CREATE TRIGGER command_run_step_attempts_payload_update_guard
BEFORE UPDATE OF stdout_text, stderr_text, error_text, stdout_crypto_version, stderr_crypto_version,
    error_crypto_version, error_plaintext_bytes ON command_run_step_attempts
WHEN (OLD.stdout_crypto_version = 1 AND NEW.stdout_crypto_version <> 1)
    OR (OLD.stderr_crypto_version = 1 AND NEW.stderr_crypto_version <> 1)
    OR (OLD.error_crypto_version = 1 AND NEW.error_crypto_version <> 1)
    OR (NEW.stdout_crypto_version = 1 AND substr(NEW.stdout_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.stderr_crypto_version = 1 AND substr(NEW.stderr_text, 1, 19) <> 'reactor-payload:v1:')
    OR (NEW.error_crypto_version = 0 AND NEW.error_plaintext_bytes IS NOT NULL)
    OR (NEW.error_crypto_version = 1 AND
        (NEW.error_plaintext_bytes IS NULL OR substr(NEW.error_text, 1, 19) <> 'reactor-payload:v1:'))
    OR (EXISTS (SELECT 1 FROM journal_payload_keys WHERE id = 'v1') AND (
        (NEW.stdout_crypto_version = 0 AND NEW.stdout_text <> ''
            AND (NEW.stdout_text IS NOT OLD.stdout_text OR NEW.stdout_crypto_version IS NOT OLD.stdout_crypto_version))
        OR (NEW.stderr_crypto_version = 0 AND NEW.stderr_text <> ''
            AND (NEW.stderr_text IS NOT OLD.stderr_text OR NEW.stderr_crypto_version IS NOT OLD.stderr_crypto_version))
        OR (NEW.error_crypto_version = 0 AND NEW.error_text <> ''
            AND (NEW.error_text IS NOT OLD.error_text OR NEW.error_crypto_version IS NOT OLD.error_crypto_version))))
BEGIN
    SELECT RAISE(ABORT, 'journal payload key exists: encrypted command output required');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_command_payload_down_guard (version INTEGER CHECK (version = 0));
INSERT INTO _reactor_command_payload_down_guard SELECT 1 FROM journal_payload_keys WHERE id = 'v1' LIMIT 1;
INSERT INTO _reactor_command_payload_down_guard
    SELECT 1 FROM command_runs WHERE error_crypto_version = 1 LIMIT 1;
INSERT INTO _reactor_command_payload_down_guard
    SELECT 1 FROM command_run_steps WHERE stdout_crypto_version = 1 OR stderr_crypto_version = 1 OR error_crypto_version = 1 LIMIT 1;
INSERT INTO _reactor_command_payload_down_guard
    SELECT 1 FROM command_run_step_attempts WHERE stdout_crypto_version = 1 OR stderr_crypto_version = 1 OR error_crypto_version = 1 LIMIT 1;
DROP TABLE _reactor_command_payload_down_guard;
DROP TRIGGER command_run_step_attempts_payload_update_guard;
DROP TRIGGER command_run_step_attempts_payload_insert_guard;
DROP TRIGGER command_run_steps_payload_update_guard;
DROP TRIGGER command_run_steps_payload_insert_guard;
DROP TRIGGER command_runs_payload_update_guard;
DROP TRIGGER command_runs_payload_insert_guard;
ALTER TABLE command_run_step_attempts DROP COLUMN error_plaintext_bytes;
ALTER TABLE command_run_step_attempts DROP COLUMN error_crypto_version;
ALTER TABLE command_run_step_attempts DROP COLUMN stderr_crypto_version;
ALTER TABLE command_run_step_attempts DROP COLUMN stdout_crypto_version;
ALTER TABLE command_run_steps DROP COLUMN error_plaintext_bytes;
ALTER TABLE command_run_steps DROP COLUMN error_crypto_version;
ALTER TABLE command_run_steps DROP COLUMN stderr_crypto_version;
ALTER TABLE command_run_steps DROP COLUMN stdout_crypto_version;
ALTER TABLE command_runs DROP COLUMN error_plaintext_bytes;
ALTER TABLE command_runs DROP COLUMN error_crypto_version;
-- +goose StatementEnd

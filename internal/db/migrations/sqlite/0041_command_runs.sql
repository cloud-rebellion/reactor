-- +goose Up
-- +goose StatementBegin

-- Durable admission and per-step receipts for a future supervised command
-- runner. These rows are intentionally separate from workflow runs: a
-- command plan is declarative data and must not be smuggled into the
-- workflow executable path.
CREATE TABLE command_runs (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    automation_id       TEXT NOT NULL REFERENCES command_automations(id) ON DELETE RESTRICT,
    automation_version  INTEGER NOT NULL,
    definition_sha256   TEXT NOT NULL,
    target              TEXT NOT NULL DEFAULT '',
    actor_id            TEXT NOT NULL,
    admission_json      TEXT NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL,
    attempt             INTEGER NOT NULL DEFAULT 0,
    claim_owner         TEXT,
    claim_token         TEXT,
    lease_expires_at    TEXT,
    error_text          TEXT,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    started_at          TEXT,
    finished_at         TEXT,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (id, tenant_id)
);
CREATE INDEX command_runs_tenant_status_idx ON command_runs(tenant_id, status, created_at, id);
CREATE INDEX command_runs_lease_idx ON command_runs(status, lease_expires_at);

CREATE TABLE command_run_steps (
    run_id              TEXT NOT NULL REFERENCES command_runs(id) ON DELETE CASCADE,
    step_seq            INTEGER NOT NULL,
    step_name           TEXT NOT NULL,
    command_sha256      TEXT NOT NULL,
    expected_exit_code  INTEGER NOT NULL,
    timeout_seconds     INTEGER NOT NULL,
    status              TEXT NOT NULL,
    attempt             INTEGER NOT NULL DEFAULT 0,
    exit_code           INTEGER,
    stdout_text         TEXT NOT NULL DEFAULT '',
    stderr_text         TEXT NOT NULL DEFAULT '',
    stdout_bytes        INTEGER NOT NULL DEFAULT 0,
    stderr_bytes        INTEGER NOT NULL DEFAULT 0,
    stdout_truncated    INTEGER NOT NULL DEFAULT 0,
    stderr_truncated    INTEGER NOT NULL DEFAULT 0,
    error_text          TEXT NOT NULL DEFAULT '',
    started_at          TEXT,
    finished_at         TEXT,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (run_id, step_seq),
    UNIQUE (run_id, step_name)
);
CREATE INDEX command_run_steps_status_idx ON command_run_steps(run_id, status, step_seq);

-- One row per actual attempt keeps crash/retry evidence instead of
-- overwriting a previous command's output in the current-step projection.
CREATE TABLE command_run_step_attempts (
    run_id              TEXT NOT NULL,
    step_seq            INTEGER NOT NULL,
    attempt             INTEGER NOT NULL,
    claim_owner         TEXT NOT NULL,
    claim_token         TEXT NOT NULL,
    status              TEXT NOT NULL,
    exit_code           INTEGER,
    stdout_text         TEXT NOT NULL DEFAULT '',
    stderr_text         TEXT NOT NULL DEFAULT '',
    stdout_bytes        INTEGER NOT NULL DEFAULT 0,
    stderr_bytes        INTEGER NOT NULL DEFAULT 0,
    stdout_truncated    INTEGER NOT NULL DEFAULT 0,
    stderr_truncated    INTEGER NOT NULL DEFAULT 0,
    error_text          TEXT NOT NULL DEFAULT '',
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (run_id, step_seq, attempt),
    FOREIGN KEY (run_id, step_seq) REFERENCES command_run_steps(run_id, step_seq) ON DELETE CASCADE
);
CREATE INDEX command_run_step_attempts_status_idx ON command_run_step_attempts(run_id, step_seq, status, attempt);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_run_steps_status_idx;
DROP INDEX IF EXISTS command_run_step_attempts_status_idx;
DROP TABLE IF EXISTS command_run_step_attempts;
DROP TABLE IF EXISTS command_run_steps;
DROP INDEX IF EXISTS command_runs_lease_idx;
DROP INDEX IF EXISTS command_runs_tenant_status_idx;
DROP TABLE IF EXISTS command_runs;
-- +goose StatementEnd

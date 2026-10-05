-- +goose Up
-- Match the bounded oldest-first retention selections in journal/retention.go.
CREATE INDEX runs_terminal_retention_idx
    ON runs (COALESCE(finished_at, created_at), id)
    WHERE status NOT IN ('running','suspended','queued');
CREATE INDEX command_runs_terminal_retention_idx
    ON command_runs (COALESCE(finished_at, created_at), id)
    WHERE status IN ('succeeded','failed','cancelled');
CREATE INDEX runs_parent_retention_idx
    ON runs (parent_run_id) WHERE parent_run_id IS NOT NULL;
CREATE INDEX command_runs_retry_retention_idx
    ON command_runs (retry_of) WHERE retry_of IS NOT NULL;

-- +goose Down
DROP INDEX command_runs_retry_retention_idx;
DROP INDEX runs_parent_retention_idx;
DROP INDEX command_runs_terminal_retention_idx;
DROP INDEX runs_terminal_retention_idx;

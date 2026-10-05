-- +goose NO TRANSACTION
-- +goose Up
-- A retention tick selects a small oldest-first terminal batch. Build these
-- partial expression indexes online so it does not repeatedly sort all run
-- history or block production writes while the index is created.
CREATE INDEX CONCURRENTLY IF NOT EXISTS runs_terminal_retention_idx
    ON runs (COALESCE(finished_at, created_at), id)
    WHERE status NOT IN ('running','suspended','queued');
CREATE INDEX CONCURRENTLY IF NOT EXISTS command_runs_terminal_retention_idx
    ON command_runs (COALESCE(finished_at, created_at), id)
    WHERE status IN ('succeeded','failed','cancelled');
-- Detaching survivors must not rescan the entire history for each batch.
CREATE INDEX CONCURRENTLY IF NOT EXISTS runs_parent_retention_idx
    ON runs (parent_run_id) WHERE parent_run_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS command_runs_retry_retention_idx
    ON command_runs (retry_of) WHERE retry_of IS NOT NULL;
-- A failed CONCURRENTLY build can leave an invalid index with its name in
-- place. IF NOT EXISTS alone would silently treat that as a completed build.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        WHERE c.relname IN (
            'runs_terminal_retention_idx',
            'command_runs_terminal_retention_idx',
            'runs_parent_retention_idx',
            'command_runs_retry_retention_idx'
        ) AND NOT i.indisvalid
    ) THEN
        RAISE EXCEPTION 'invalid Reactor retention index; drop it concurrently and rerun migration';
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS command_runs_retry_retention_idx;
DROP INDEX CONCURRENTLY IF EXISTS runs_parent_retention_idx;
DROP INDEX CONCURRENTLY IF EXISTS command_runs_terminal_retention_idx;
DROP INDEX CONCURRENTLY IF EXISTS runs_terminal_retention_idx;

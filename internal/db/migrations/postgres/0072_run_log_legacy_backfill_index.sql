-- +goose NO TRANSACTION
-- +goose Up
-- Build without blocking the live run-log writer while an operator prepares
-- the explicit historical backfill.
CREATE INDEX CONCURRENTLY IF NOT EXISTS run_logs_legacy_backfill_idx
ON run_logs (run_id, seq) WHERE payload_crypto_version = 0;
-- A failed concurrent build can leave an invalid same-name index. IF NOT
-- EXISTS would then skip the rebuild and falsely report a completed migration.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
          AND c.relname = 'run_logs_legacy_backfill_idx'
          AND NOT i.indisvalid
    ) THEN
        RAISE EXCEPTION 'invalid Reactor run-log backfill index; drop it concurrently and rerun migration';
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS run_logs_legacy_backfill_idx;

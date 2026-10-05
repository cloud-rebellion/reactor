-- +goose NO TRANSACTION
-- +goose Up
-- A worker fetches only the oldest bounded slice of each workflow's queue.
-- Build the partial index online so the migration does not block enqueues.
CREATE INDEX CONCURRENTLY IF NOT EXISTS runs_queued_workflow_order_idx
    ON runs (workflow_id, created_at, id)
    INCLUDE (tenant_id)
    WHERE status = 'queued' AND cancel_requested = false;

-- This is an append-only membership hint, not an execution authority. A
-- workflow stays here after its queue drains and disappears with the workflow.
-- Keeping the row avoids a hot per-workflow counter/lock on every enqueue.
CREATE TABLE IF NOT EXISTS queue_workflow_index (
    workflow_id TEXT PRIMARY KEY REFERENCES workflows(id) ON DELETE CASCADE
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reactor_index_queued_workflow() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO queue_workflow_index (workflow_id) VALUES (NEW.workflow_id)
        ON CONFLICT (workflow_id) DO NOTHING;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS runs_queue_workflow_index_trg ON runs;
CREATE TRIGGER runs_queue_workflow_index_trg
    AFTER INSERT OR UPDATE OF status, cancel_requested, workflow_id ON runs
    FOR EACH ROW WHEN (NEW.status = 'queued' AND NEW.cancel_requested = false)
    EXECUTE FUNCTION reactor_index_queued_workflow();

-- Install the trigger before backfilling: even old application writers are
-- captured while the one-time scan runs. The conflict clause makes reruns safe.
INSERT INTO queue_workflow_index (workflow_id)
    SELECT DISTINCT workflow_id FROM runs
    WHERE status = 'queued' AND cancel_requested = false
    ON CONFLICT (workflow_id) DO NOTHING;

-- A failed concurrent build can leave an invalid index. Refuse to mark this
-- migration complete until an operator removes the invalid index and retries.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        WHERE c.relname = 'runs_queued_workflow_order_idx' AND NOT i.indisvalid
    ) THEN
        RAISE EXCEPTION 'invalid Reactor queue index; drop it concurrently and rerun migration';
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS runs_queue_workflow_index_trg ON runs;
DROP FUNCTION IF EXISTS reactor_index_queued_workflow();
DROP TABLE IF EXISTS queue_workflow_index;
DROP INDEX CONCURRENTLY IF EXISTS runs_queued_workflow_order_idx;

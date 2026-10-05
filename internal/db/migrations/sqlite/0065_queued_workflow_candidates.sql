-- +goose Up
-- +goose StatementBegin
-- SQLite is local-only and retains the existing fair queue select. Mirror the
-- partial queue index for inexpensive per-workflow reads and schema parity.
CREATE INDEX runs_queued_workflow_order_idx ON runs (workflow_id, created_at, id)
    WHERE status = 'queued' AND cancel_requested = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runs_queued_workflow_order_idx;
-- +goose StatementEnd

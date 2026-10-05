-- +goose Up
-- +goose StatementBegin
-- Bound the oldest-backlog probe to eligible queued rows in creation order.
CREATE INDEX runs_queued_oldest_idx ON runs(created_at, id)
    WHERE status = 'queued' AND cancel_requested = false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runs_queued_oldest_idx;
-- +goose StatementEnd

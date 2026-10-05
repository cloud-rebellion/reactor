-- +goose Up
-- +goose StatementBegin
-- Keep the local queue-age probe efficient without scanning run history.
CREATE INDEX runs_queued_oldest_idx ON runs(created_at, id)
    WHERE status = 'queued' AND cancel_requested = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runs_queued_oldest_idx;
-- +goose StatementEnd

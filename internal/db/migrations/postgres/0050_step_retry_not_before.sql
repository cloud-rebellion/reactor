-- +goose Up
ALTER TABLE steps ADD COLUMN retry_not_before TIMESTAMPTZ;

-- +goose Down
ALTER TABLE steps DROP COLUMN retry_not_before;

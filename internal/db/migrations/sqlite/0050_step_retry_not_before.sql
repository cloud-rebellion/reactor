-- +goose Up
ALTER TABLE steps ADD COLUMN retry_not_before TEXT;

-- +goose Down
ALTER TABLE steps DROP COLUMN retry_not_before;

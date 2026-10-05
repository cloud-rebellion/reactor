-- +goose Up
-- +goose StatementBegin

-- SQLite stores trigger metadata as TEXT. Keep a byte-for-byte copy as BLOB
-- so the queue and local execution paths share one trigger input contract.
ALTER TABLE runs ADD COLUMN trigger_input BLOB;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE runs DROP COLUMN trigger_input;
-- +goose StatementEnd

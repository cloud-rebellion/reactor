-- +goose Up
-- +goose StatementBegin

-- Monotonic control-plane revision used by scoped MCP trigger mutations.
-- Runtime bookkeeping also advances it, so a stale authoring read cannot
-- silently overwrite a fire/error/state change made after that read.
ALTER TABLE triggers ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE triggers DROP COLUMN revision;
-- +goose StatementEnd

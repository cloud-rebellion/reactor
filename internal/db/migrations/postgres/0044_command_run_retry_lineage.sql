-- +goose Up
-- +goose StatementBegin

-- Explicit retry lineage is metadata only. It never copies command text,
-- output, credentials, or claim state from the source run.
ALTER TABLE command_runs ADD COLUMN retry_of TEXT;
CREATE INDEX command_runs_retry_of_idx ON command_runs(tenant_id, retry_of);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_runs_retry_of_idx;
ALTER TABLE command_runs DROP COLUMN retry_of;
-- +goose StatementEnd

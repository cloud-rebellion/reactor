-- +goose Up
-- +goose StatementBegin

-- Optional client-supplied idempotency for manual MCP dispatches. The key is
-- scoped to the workflow (and therefore its tenant) and is bound to the exact
-- payload digest so a reused key cannot silently run different data.
ALTER TABLE runs ADD COLUMN dispatch_idempotency_key TEXT;
ALTER TABLE runs ADD COLUMN dispatch_payload_sha256 TEXT;
CREATE UNIQUE INDEX runs_dispatch_idempotency_idx
    ON runs(workflow_id, dispatch_idempotency_key)
    WHERE dispatch_idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runs_dispatch_idempotency_idx;
ALTER TABLE runs DROP COLUMN dispatch_payload_sha256;
ALTER TABLE runs DROP COLUMN dispatch_idempotency_key;
-- +goose StatementEnd

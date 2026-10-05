-- +goose Up
-- +goose StatementBegin

-- Caller-supplied keys make HTTP trigger creation safe to retry after a lost
-- response. The key is scoped to the tenant, workflow, and trigger kind so
-- unrelated workflows may reuse a natural operation id.
ALTER TABLE triggers ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX triggers_create_idempotency_idx
    ON triggers(tenant_id, workflow_id, kind, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS triggers_create_idempotency_idx;
ALTER TABLE triggers DROP COLUMN idempotency_key;
-- +goose StatementEnd

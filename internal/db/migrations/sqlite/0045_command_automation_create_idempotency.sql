-- +goose Up
-- +goose StatementBegin

-- Optional caller keys make command-plan creation safe to retry after a lost
-- HTTP response. The key is scoped to a tenant; the digest binds it to the
-- exact normalized metadata, actor, and version-1 definition it first saw.
ALTER TABLE command_automations ADD COLUMN idempotency_key TEXT;
ALTER TABLE command_automations ADD COLUMN idempotency_hash TEXT;
CREATE UNIQUE INDEX command_automations_create_idempotency_idx
    ON command_automations(tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS command_automations_create_idempotency_idx;
ALTER TABLE command_automations DROP COLUMN idempotency_hash;
ALTER TABLE command_automations DROP COLUMN idempotency_key;
-- +goose StatementEnd

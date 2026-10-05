-- +goose Up
-- +goose StatementBegin
-- Keep the operator's unresolved-send inventory tenant-indexed. Existing
-- intents inherit the immutable owner of their run; no message data is copied.
ALTER TABLE mail_send_intents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'
    CHECK (length(tenant_id) > 0);
UPDATE mail_send_intents SET tenant_id =
    (SELECT tenant_id FROM runs WHERE runs.id = mail_send_intents.run_id);
CREATE INDEX mail_send_intents_tenant_status_time_idx
    ON mail_send_intents(tenant_id, status, created_at DESC, id DESC);
-- Older writers may omit the new column during a drain. Resolve ownership
-- from the run itself so their rows cannot silently land under default.
CREATE TRIGGER mail_send_intents_tenant_insert AFTER INSERT ON mail_send_intents
WHEN NEW.tenant_id <> (SELECT tenant_id FROM runs WHERE id = NEW.run_id)
BEGIN
    UPDATE mail_send_intents SET tenant_id =
        (SELECT tenant_id FROM runs WHERE id = NEW.run_id) WHERE id = NEW.id;
END;
CREATE TRIGGER mail_send_intents_tenant_update AFTER UPDATE OF run_id, tenant_id ON mail_send_intents
WHEN NEW.tenant_id <> (SELECT tenant_id FROM runs WHERE id = NEW.run_id)
BEGIN
    UPDATE mail_send_intents SET tenant_id =
        (SELECT tenant_id FROM runs WHERE id = NEW.run_id) WHERE id = NEW.id;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS mail_send_intents_tenant_update;
DROP TRIGGER IF EXISTS mail_send_intents_tenant_insert;
DROP INDEX IF EXISTS mail_send_intents_tenant_status_time_idx;
ALTER TABLE mail_send_intents DROP COLUMN tenant_id;
-- +goose StatementEnd

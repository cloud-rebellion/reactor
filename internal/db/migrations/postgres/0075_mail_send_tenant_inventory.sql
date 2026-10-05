-- +goose Up
-- +goose StatementBegin
-- Keep the operator's unresolved-send inventory tenant-indexed. Existing
-- intents inherit the immutable owner of their run; no message data is copied.
ALTER TABLE mail_send_intents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'
    CHECK (length(tenant_id) > 0);
UPDATE mail_send_intents m SET tenant_id = r.tenant_id
    FROM runs r WHERE r.id = m.run_id;
CREATE INDEX mail_send_intents_tenant_status_time_idx
    ON mail_send_intents(tenant_id, status, created_at DESC, id DESC);
-- Resolve ownership from the run even for older writers that omit tenant_id
-- during a drain, or for a caller that supplied a stale tenant.
CREATE FUNCTION mail_send_intents_set_tenant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT tenant_id INTO NEW.tenant_id FROM runs WHERE id = NEW.run_id;
    RETURN NEW;
END $$;
CREATE TRIGGER mail_send_intents_tenant_write
BEFORE INSERT OR UPDATE OF run_id, tenant_id ON mail_send_intents
FOR EACH ROW EXECUTE FUNCTION mail_send_intents_set_tenant();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS mail_send_intents_tenant_write ON mail_send_intents;
DROP FUNCTION IF EXISTS mail_send_intents_set_tenant();
DROP INDEX IF EXISTS mail_send_intents_tenant_status_time_idx;
ALTER TABLE mail_send_intents DROP COLUMN tenant_id;
-- +goose StatementEnd

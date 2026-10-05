-- +goose Up
-- +goose StatementBegin
-- A resolution is an operator's recorded finding, never a provider callback or
-- permission to replay the send. Keep the original admitted intent unchanged.
CREATE TABLE mail_send_resolutions (
    id              TEXT PRIMARY KEY,
    intent_id       TEXT NOT NULL UNIQUE REFERENCES mail_send_intents(id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
    run_id          TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 512),
    decision        TEXT NOT NULL CHECK (decision IN ('provider_accepted', 'provider_rejected', 'closed_unverified')),
    evidence_kind   TEXT NOT NULL CHECK (evidence_kind IN ('provider_record', 'provider_audit', 'manual_decision')),
    evidence_sha256 TEXT NOT NULL CHECK (length(evidence_sha256) = 64),
    actor_id        TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 512),
    resolved_at     TEXT NOT NULL
);
CREATE TRIGGER mail_send_resolutions_owner
BEFORE INSERT ON mail_send_resolutions
WHEN NOT EXISTS (
    SELECT 1 FROM mail_send_intents m JOIN runs r ON r.id = m.run_id
    WHERE m.id = NEW.intent_id AND m.tenant_id = NEW.tenant_id
      AND m.run_id = NEW.run_id AND m.status = 'admitted'
      AND r.status NOT IN ('running', 'queued', 'suspended')
      AND NOT EXISTS (SELECT 1 FROM leases l WHERE l.run_id = m.run_id)
)
BEGIN
    SELECT RAISE(ABORT, 'mail send resolution owner or status mismatch');
END;
CREATE TRIGGER mail_send_resolutions_immutable
BEFORE UPDATE ON mail_send_resolutions
BEGIN
    SELECT RAISE(ABORT, 'mail send resolution is immutable');
END;
CREATE TRIGGER mail_send_intents_no_confirm_after_resolution
BEFORE UPDATE OF status ON mail_send_intents
WHEN NEW.status = 'confirmed' AND EXISTS (
    SELECT 1 FROM mail_send_resolutions x WHERE x.intent_id = OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'mail send has an operator resolution');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS mail_send_resolutions_immutable;
DROP TRIGGER IF EXISTS mail_send_resolutions_owner;
DROP TRIGGER IF EXISTS mail_send_intents_no_confirm_after_resolution;
DROP TABLE IF EXISTS mail_send_resolutions;
-- +goose StatementEnd

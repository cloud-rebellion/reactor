-- +goose Up
-- +goose StatementBegin
ALTER TABLE runs ADD COLUMN terminal_generation BIGINT NOT NULL DEFAULT 0
    CHECK (terminal_generation >= 0);
CREATE FUNCTION set_run_terminal_generation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IN ('succeeded', 'failed', 'failed_dlq')
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.terminal_generation := OLD.terminal_generation + 1;
    ELSE
        NEW.terminal_generation := OLD.terminal_generation;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER runs_terminal_generation_update BEFORE UPDATE OF status ON runs
FOR EACH ROW EXECUTE FUNCTION set_run_terminal_generation();

CREATE TABLE notification_dispatches (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'failed_dlq')),
    workflow_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, generation, status)
);
CREATE TABLE notification_deliveries (
    run_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    status TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    delivered_at TIMESTAMPTZ,
    skipped_at TIMESTAMPTZ,
    PRIMARY KEY (run_id, generation, status, channel_id),
    FOREIGN KEY (run_id, generation, status)
        REFERENCES notification_dispatches(run_id, generation, status) ON DELETE CASCADE,
    CHECK (delivered_at IS NULL OR skipped_at IS NULL)
);

CREATE FUNCTION guard_terminal_effect_notification_ack() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.delivered_at IS NOT NULL AND OLD.delivered_at IS NULL AND (
        EXISTS (
            SELECT 1 FROM workflow_notification_routes route
            JOIN runs run ON run.workflow_id = route.workflow_id
            WHERE run.id = NEW.run_id
        ) OR EXISTS (SELECT 1 FROM notification_dispatches snap WHERE snap.run_id = NEW.run_id)
    ) AND (
        NOT EXISTS (
            SELECT 1 FROM notification_dispatches snap
            JOIN runs run ON run.id = snap.run_id
            WHERE snap.run_id = NEW.run_id AND snap.generation = run.terminal_generation
                AND snap.status = NEW.status AND snap.workflow_id = run.workflow_id
                AND snap.tenant_id = run.tenant_id
        ) OR EXISTS (
            SELECT 1 FROM notification_deliveries delivery
            JOIN runs run ON run.id = delivery.run_id
            WHERE delivery.run_id = NEW.run_id AND delivery.generation = run.terminal_generation
                AND delivery.status = NEW.status
                AND delivery.delivered_at IS NULL AND delivery.skipped_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION 'notification deliveries not acknowledged';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER terminal_effect_notification_ack_guard
BEFORE UPDATE OF delivered_at ON terminal_effects
FOR EACH ROW EXECUTE FUNCTION guard_terminal_effect_notification_ack();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM notification_dispatches) THEN
        RAISE EXCEPTION 'cannot roll back notification delivery receipts while snapshots exist';
    END IF;
END $$;
DROP TRIGGER terminal_effect_notification_ack_guard ON terminal_effects;
DROP FUNCTION guard_terminal_effect_notification_ack();
DROP TABLE notification_deliveries;
DROP TABLE notification_dispatches;
DROP TRIGGER runs_terminal_generation_update ON runs;
DROP FUNCTION set_run_terminal_generation();
ALTER TABLE runs DROP COLUMN terminal_generation;
-- +goose StatementEnd

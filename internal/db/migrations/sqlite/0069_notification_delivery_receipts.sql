-- +goose Up
-- +goose StatementBegin
-- A reused run ID can finish again after a dead-letter redrive, including with
-- the same status. A counter avoids timestamp collisions when fencing alerts.
ALTER TABLE runs ADD COLUMN terminal_generation INTEGER NOT NULL DEFAULT 0
    CHECK (terminal_generation >= 0);
CREATE TRIGGER runs_terminal_generation_update AFTER UPDATE OF status ON runs
WHEN NEW.status IN ('succeeded', 'failed', 'failed_dlq') AND NEW.status IS NOT OLD.status
BEGIN
    UPDATE runs SET terminal_generation = OLD.terminal_generation + 1 WHERE id = NEW.id;
END;

-- Freeze channel membership once per terminal generation. The ledger contains
-- only IDs and timestamps; channel config and vault values stay elsewhere.
CREATE TABLE notification_dispatches (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'failed_dlq')),
    workflow_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (run_id, generation, status)
);
CREATE TABLE notification_deliveries (
    run_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    status TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    delivered_at TEXT,
    skipped_at TEXT,
    PRIMARY KEY (run_id, generation, status, channel_id),
    FOREIGN KEY (run_id, generation, status)
        REFERENCES notification_dispatches(run_id, generation, status) ON DELETE CASCADE,
    CHECK (delivered_at IS NULL OR skipped_at IS NULL)
);

-- An old daemon has no channel receipts. It may still send, but must not
-- acknowledge a terminal effect while active routes or unfinished receipts
-- exist. A current daemon snapshots routes (including an empty snapshot).
CREATE TRIGGER terminal_effect_notification_ack_guard
BEFORE UPDATE OF delivered_at ON terminal_effects
WHEN NEW.delivered_at IS NOT NULL AND OLD.delivered_at IS NULL AND (
    EXISTS (
        SELECT 1 FROM workflow_notification_routes route
        JOIN runs run ON run.workflow_id = route.workflow_id
        WHERE run.id = NEW.run_id
    )
    OR EXISTS (SELECT 1 FROM notification_dispatches snap WHERE snap.run_id = NEW.run_id)
) AND (
    NOT EXISTS (
        SELECT 1 FROM notification_dispatches snap
        JOIN runs run ON run.id = snap.run_id
        WHERE snap.run_id = NEW.run_id AND snap.generation = run.terminal_generation
            AND snap.status = NEW.status AND snap.workflow_id = run.workflow_id
            AND snap.tenant_id = run.tenant_id
    )
    OR EXISTS (
        SELECT 1 FROM notification_deliveries delivery
        JOIN runs run ON run.id = delivery.run_id
        WHERE delivery.run_id = NEW.run_id AND delivery.generation = run.terminal_generation
            AND delivery.status = NEW.status
            AND delivery.delivered_at IS NULL AND delivery.skipped_at IS NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'notification deliveries not acknowledged');
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_notification_delivery_down_guard (empty INTEGER CHECK (empty = 0));
INSERT INTO _reactor_notification_delivery_down_guard SELECT 1 FROM notification_dispatches LIMIT 1;
DROP TABLE _reactor_notification_delivery_down_guard;
DROP TRIGGER terminal_effect_notification_ack_guard;
DROP TABLE notification_deliveries;
DROP TABLE notification_dispatches;
DROP TRIGGER runs_terminal_generation_update;
ALTER TABLE runs DROP COLUMN terminal_generation;
-- +goose StatementEnd

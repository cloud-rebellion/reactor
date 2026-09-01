-- +goose Up
-- +goose StatementBegin

-- Lease a verified webhook receipt until its workflow run has been durably
-- created. Without this state, a crash between the old dedup INSERT and run
-- creation permanently suppressed every provider retry.
ALTER TABLE webhook_deliveries ADD COLUMN payload_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE webhook_deliveries ADD COLUMN claim_token TEXT NOT NULL DEFAULT '';
ALTER TABLE webhook_deliveries ADD COLUMN lease_expires_at TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN completed_at TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN run_id TEXT;

-- Existing receipts were acknowledged under the old contract. Preserve them
-- as completed legacy rows; the empty digest is their sentinel value.
UPDATE webhook_deliveries SET completed_at = received_at;

CREATE INDEX webhook_deliveries_active_lease_idx
    ON webhook_deliveries(lease_expires_at)
    WHERE completed_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS webhook_deliveries_active_lease_idx;

-- Rebuild to the exact 0025 shape. webhook_deliveries has no foreign keys in
-- either direction, so the rename/drop cannot retarget child references.
ALTER TABLE webhook_deliveries RENAME TO webhook_deliveries_with_leases;
CREATE TABLE webhook_deliveries (
    trigger_id   TEXT NOT NULL DEFAULT '',
    provider     TEXT NOT NULL,
    delivery_id  TEXT NOT NULL,
    received_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (trigger_id, provider, delivery_id)
);
INSERT INTO webhook_deliveries (trigger_id, provider, delivery_id, received_at)
SELECT trigger_id, provider, delivery_id, received_at
FROM webhook_deliveries_with_leases;
DROP TABLE webhook_deliveries_with_leases;
CREATE INDEX webhook_deliveries_received_idx ON webhook_deliveries(received_at);
-- +goose StatementEnd

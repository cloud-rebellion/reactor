-- +goose Up
-- +goose StatementBegin

-- A webhook receipt used to become a permanent dedup row before the
-- dispatcher had durably created its run. A process crash in that window made
-- every provider retry look completed even though no workflow ever ran.
--
-- New receipts are leased until dispatch has created a run, then marked
-- completed. An expired lease can be reclaimed, so a crash may produce an
-- at-least-once retry but can no longer permanently eat the delivery. The
-- payload digest also prevents one delivery id from silently aliasing two
-- different request bodies.

ALTER TABLE webhook_deliveries
    ADD COLUMN payload_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN claim_token TEXT NOT NULL DEFAULT '',
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN completed_at TIMESTAMPTZ,
    ADD COLUMN run_id TEXT;

-- Pre-0028 rows were already acknowledged under the old dedup contract. Keep
-- them completed instead of replaying up to seven days of historical events
-- after upgrade. Their empty digest is an explicit legacy sentinel.
UPDATE webhook_deliveries SET completed_at = received_at;

CREATE INDEX webhook_deliveries_active_lease_idx
    ON webhook_deliveries(lease_expires_at)
    WHERE completed_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS webhook_deliveries_active_lease_idx;
ALTER TABLE webhook_deliveries
    DROP COLUMN run_id,
    DROP COLUMN completed_at,
    DROP COLUMN lease_expires_at,
    DROP COLUMN claim_token,
    DROP COLUMN payload_sha256;
-- +goose StatementEnd

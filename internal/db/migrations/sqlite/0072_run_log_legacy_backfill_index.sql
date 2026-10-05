-- +goose Up
-- Keep repeated bounded historical backfill batches from rescanning the
-- already-sealed prefix of a large run_logs table.
CREATE INDEX IF NOT EXISTS run_logs_legacy_backfill_idx
ON run_logs (run_id, seq) WHERE payload_crypto_version = 0;

-- +goose Down
DROP INDEX IF EXISTS run_logs_legacy_backfill_idx;

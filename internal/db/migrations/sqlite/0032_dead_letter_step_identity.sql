-- +goose Up
-- +goose StatementBegin

-- Durable DLQ rows identify the exact failed step attempt. Nullable columns
-- preserve legacy rows written before attempt ordinals were carried into DLQ.
ALTER TABLE dead_letter ADD COLUMN step_seq INTEGER;
ALTER TABLE dead_letter ADD COLUMN step_attempt INTEGER;
ALTER TABLE dead_letter ADD COLUMN failure_order INTEGER;

-- Backfill a stable per-run order for legacy rows. Equal timestamps are broken
-- by opaque id so the result is deterministic even though old inserts did not
-- carry an explicit sequence.
UPDATE dead_letter AS d
SET failure_order = (
    SELECT COUNT(*) FROM dead_letter AS prior
    WHERE prior.run_id = d.run_id
      AND (prior.moved_at < d.moved_at
           OR (prior.moved_at = d.moved_at AND prior.id <= d.id))
);

CREATE UNIQUE INDEX dead_letter_step_attempt_uidx
    ON dead_letter(run_id, step_seq, step_name, step_attempt)
    WHERE step_seq IS NOT NULL AND step_attempt IS NOT NULL;
CREATE UNIQUE INDEX dead_letter_failure_order_uidx
    ON dead_letter(run_id, failure_order)
    WHERE failure_order IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS dead_letter_step_attempt_uidx;
DROP INDEX IF EXISTS dead_letter_failure_order_uidx;
ALTER TABLE dead_letter DROP COLUMN failure_order;
ALTER TABLE dead_letter DROP COLUMN step_attempt;
ALTER TABLE dead_letter DROP COLUMN step_seq;

-- +goose StatementEnd

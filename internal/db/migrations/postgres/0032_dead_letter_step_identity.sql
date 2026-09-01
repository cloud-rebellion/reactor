-- +goose Up
-- +goose StatementBegin

-- Durable DLQ rows identify the exact failed step attempt. Nullable columns
-- preserve legacy rows written before attempt ordinals were carried into DLQ.
ALTER TABLE dead_letter ADD COLUMN step_seq BIGINT;
ALTER TABLE dead_letter ADD COLUMN step_attempt INTEGER;
ALTER TABLE dead_letter ADD COLUMN failure_order BIGINT;

WITH ordered AS (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY run_id ORDER BY moved_at, id) AS n
    FROM dead_letter
)
UPDATE dead_letter d SET failure_order = ordered.n
FROM ordered WHERE ordered.id = d.id;

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

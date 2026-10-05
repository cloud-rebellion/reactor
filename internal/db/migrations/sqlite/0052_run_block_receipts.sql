-- +goose Up
-- +goose StatementBegin
CREATE TABLE run_block_receipts (
    run_id       TEXT NOT NULL,
    step_name    TEXT NOT NULL,
    seq          INTEGER NOT NULL CHECK (seq > 0),
    attempt      INTEGER NOT NULL CHECK (attempt > 0),
    call_ordinal INTEGER NOT NULL CHECK (call_ordinal BETWEEN 1 AND 128),
    block_id     TEXT NOT NULL CHECK (length(block_id) BETWEEN 1 AND 128),
    kind         TEXT NOT NULL CHECK (kind = 'merge'),
    mode         TEXT NOT NULL CHECK (mode IN ('inner_join','left_join','right_join','full_join')),
    left_rows    INTEGER NOT NULL CHECK (left_rows BETWEEN 0 AND 100000),
    right_rows   INTEGER NOT NULL CHECK (right_rows BETWEEN 0 AND 100000),
    output_rows  INTEGER NOT NULL CHECK (output_rows BETWEEN 0 AND 100000),
    max_rows     INTEGER NOT NULL CHECK (max_rows BETWEEN 1 AND 100000),
    outcome      TEXT NOT NULL CHECK (outcome IN ('succeeded','bounded_failure')),
    observed_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (run_id, seq, step_name, attempt, call_ordinal),
    FOREIGN KEY (run_id, seq, step_name, attempt)
        REFERENCES steps(run_id, seq, step_name, attempt) ON DELETE CASCADE
);
CREATE INDEX run_block_receipts_run_recent_idx
    ON run_block_receipts(run_id, seq DESC, attempt DESC, call_ordinal DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS run_block_receipts_run_recent_idx;
DROP TABLE IF EXISTS run_block_receipts;
-- +goose StatementEnd

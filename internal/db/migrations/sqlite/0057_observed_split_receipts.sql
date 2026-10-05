-- +goose Up
-- +goose StatementBegin
CREATE TABLE run_block_receipts_next (
    run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq > 0),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    call_ordinal INTEGER NOT NULL CHECK (call_ordinal BETWEEN 1 AND 128),
    block_id TEXT NOT NULL CHECK (length(block_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (kind IN ('merge','split')),
    mode TEXT NOT NULL,
    left_rows INTEGER NOT NULL CHECK (left_rows BETWEEN 0 AND 100000),
    right_rows INTEGER NOT NULL CHECK (right_rows BETWEEN 0 AND 100000),
    output_rows INTEGER NOT NULL CHECK (output_rows BETWEEN 0 AND 100000),
    max_rows INTEGER NOT NULL CHECK (max_rows BETWEEN 0 AND 100000),
    input_rows INTEGER CHECK (input_rows BETWEEN 0 AND 100000),
    yes_rows INTEGER CHECK (yes_rows BETWEEN 0 AND 100000),
    no_rows INTEGER CHECK (no_rows BETWEEN 0 AND 100000),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','bounded_failure')),
    observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CONSTRAINT run_block_receipts_shape CHECK (
        (kind = 'merge' AND mode IN ('inner_join','left_join','right_join','full_join')
            AND max_rows BETWEEN 1 AND 100000 AND output_rows <= max_rows
            AND (outcome != 'bounded_failure' OR output_rows = 0)
            AND input_rows IS NULL AND yes_rows IS NULL AND no_rows IS NULL)
        OR (kind = 'split' AND mode = '' AND left_rows = 0 AND right_rows = 0
            AND output_rows = 0 AND max_rows = 0 AND outcome = 'succeeded'
            AND input_rows IS NOT NULL AND yes_rows IS NOT NULL AND no_rows IS NOT NULL
            AND yes_rows + no_rows = input_rows)
    ),
    PRIMARY KEY (run_id, seq, step_name, attempt, call_ordinal),
    FOREIGN KEY (run_id, seq, step_name, attempt)
        REFERENCES steps(run_id, seq, step_name, attempt) ON DELETE CASCADE
);
INSERT INTO run_block_receipts_next
    (run_id, step_name, seq, attempt, call_ordinal, block_id, kind, mode,
     left_rows, right_rows, output_rows, max_rows, outcome, observed_at)
SELECT run_id, step_name, seq, attempt, call_ordinal, block_id, kind, mode,
       left_rows, right_rows, output_rows, max_rows, outcome, observed_at
FROM run_block_receipts;
DROP TABLE run_block_receipts;
ALTER TABLE run_block_receipts_next RENAME TO run_block_receipts;
CREATE INDEX run_block_receipts_run_recent_idx
    ON run_block_receipts(run_id, seq DESC, attempt DESC, call_ordinal DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE run_block_receipts_previous (
    run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq > 0),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    call_ordinal INTEGER NOT NULL CHECK (call_ordinal BETWEEN 1 AND 128),
    block_id TEXT NOT NULL CHECK (length(block_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (kind = 'merge'),
    mode TEXT NOT NULL CHECK (mode IN ('inner_join','left_join','right_join','full_join')),
    left_rows INTEGER NOT NULL CHECK (left_rows BETWEEN 0 AND 100000),
    right_rows INTEGER NOT NULL CHECK (right_rows BETWEEN 0 AND 100000),
    output_rows INTEGER NOT NULL CHECK (output_rows BETWEEN 0 AND 100000),
    max_rows INTEGER NOT NULL CHECK (max_rows BETWEEN 1 AND 100000),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','bounded_failure')),
    observed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (run_id, seq, step_name, attempt, call_ordinal),
    FOREIGN KEY (run_id, seq, step_name, attempt)
        REFERENCES steps(run_id, seq, step_name, attempt) ON DELETE CASCADE
);
INSERT INTO run_block_receipts_previous
    (run_id, step_name, seq, attempt, call_ordinal, block_id, kind, mode,
     left_rows, right_rows, output_rows, max_rows, outcome, observed_at)
SELECT run_id, step_name, seq, attempt, call_ordinal, block_id, kind, mode,
       left_rows, right_rows, output_rows, max_rows, outcome, observed_at
FROM run_block_receipts WHERE kind = 'merge';
DROP TABLE run_block_receipts;
ALTER TABLE run_block_receipts_previous RENAME TO run_block_receipts;
CREATE INDEX run_block_receipts_run_recent_idx
    ON run_block_receipts(run_id, seq DESC, attempt DESC, call_ordinal DESC);
-- +goose StatementEnd

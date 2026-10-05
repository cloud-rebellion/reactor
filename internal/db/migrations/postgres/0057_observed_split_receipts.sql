-- +goose Up
-- +goose StatementBegin
ALTER TABLE run_block_receipts
    ADD COLUMN input_rows INT,
    ADD COLUMN yes_rows INT,
    ADD COLUMN no_rows INT;
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_kind_check;
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_mode_check;
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_max_rows_check;
ALTER TABLE run_block_receipts
    ADD CONSTRAINT run_block_receipts_kind_check CHECK (kind IN ('merge','split')),
    ADD CONSTRAINT run_block_receipts_max_rows_check CHECK (max_rows BETWEEN 0 AND 100000),
    ADD CONSTRAINT run_block_receipts_input_rows_check CHECK (input_rows BETWEEN 0 AND 100000),
    ADD CONSTRAINT run_block_receipts_yes_rows_check CHECK (yes_rows BETWEEN 0 AND 100000),
    ADD CONSTRAINT run_block_receipts_no_rows_check CHECK (no_rows BETWEEN 0 AND 100000),
    ADD CONSTRAINT run_block_receipts_shape_check CHECK (
        (kind = 'merge' AND mode IN ('inner_join','left_join','right_join','full_join')
            AND max_rows BETWEEN 1 AND 100000 AND output_rows <= max_rows
            AND (outcome != 'bounded_failure' OR output_rows = 0)
            AND input_rows IS NULL AND yes_rows IS NULL AND no_rows IS NULL)
        OR (kind = 'split' AND mode = '' AND left_rows = 0 AND right_rows = 0
            AND output_rows = 0 AND max_rows = 0 AND outcome = 'succeeded'
            AND input_rows IS NOT NULL AND yes_rows IS NOT NULL AND no_rows IS NOT NULL
            AND yes_rows + no_rows = input_rows)
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM run_block_receipts WHERE kind = 'split';
ALTER TABLE run_block_receipts
    DROP CONSTRAINT run_block_receipts_shape_check,
    DROP CONSTRAINT run_block_receipts_input_rows_check,
    DROP CONSTRAINT run_block_receipts_yes_rows_check,
    DROP CONSTRAINT run_block_receipts_no_rows_check,
    DROP CONSTRAINT run_block_receipts_kind_check,
    DROP CONSTRAINT run_block_receipts_max_rows_check;
ALTER TABLE run_block_receipts
    ADD CONSTRAINT run_block_receipts_kind_check CHECK (kind = 'merge'),
    ADD CONSTRAINT run_block_receipts_mode_check CHECK (mode IN ('inner_join','left_join','right_join','full_join')),
    ADD CONSTRAINT run_block_receipts_max_rows_check CHECK (max_rows BETWEEN 1 AND 100000);
ALTER TABLE run_block_receipts
    DROP COLUMN input_rows,
    DROP COLUMN yes_rows,
    DROP COLUMN no_rows;
-- +goose StatementEnd

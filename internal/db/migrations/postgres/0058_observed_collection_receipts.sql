-- +goose Up
-- +goose StatementBegin
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_kind_check;
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_shape_check;
ALTER TABLE run_block_receipts
    ADD CONSTRAINT run_block_receipts_kind_check CHECK (kind IN ('merge','split','iterate','aggregate')),
    ADD CONSTRAINT run_block_receipts_shape_check CHECK (
        (kind = 'merge' AND mode IN ('inner_join','left_join','right_join','full_join')
            AND max_rows BETWEEN 1 AND 100000 AND output_rows <= max_rows
            AND (outcome != 'bounded_failure' OR output_rows = 0)
            AND input_rows IS NULL AND yes_rows IS NULL AND no_rows IS NULL)
        OR (kind = 'split' AND mode = '' AND left_rows = 0 AND right_rows = 0
            AND output_rows = 0 AND max_rows = 0 AND outcome = 'succeeded'
            AND input_rows IS NOT NULL AND yes_rows IS NOT NULL AND no_rows IS NOT NULL
            AND yes_rows + no_rows = input_rows)
        OR (kind = 'iterate' AND mode = '' AND left_rows = 0 AND right_rows = 0
            AND max_rows = 0 AND outcome = 'succeeded' AND input_rows IS NOT NULL
            AND output_rows = input_rows AND yes_rows IS NULL AND no_rows IS NULL)
        OR (kind = 'aggregate' AND mode = '' AND left_rows = 0 AND right_rows = 0
            AND max_rows = 0 AND outcome = 'succeeded' AND input_rows IS NOT NULL
            AND output_rows = 1 AND yes_rows IS NULL AND no_rows IS NULL)
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM run_block_receipts WHERE kind IN ('iterate','aggregate');
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_kind_check;
ALTER TABLE run_block_receipts DROP CONSTRAINT run_block_receipts_shape_check;
ALTER TABLE run_block_receipts
    ADD CONSTRAINT run_block_receipts_kind_check CHECK (kind IN ('merge','split')),
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

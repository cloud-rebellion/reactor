-- +goose Up
-- +goose StatementBegin

-- JSONB is useful for querying trigger metadata, but it canonicalises the
-- input bytes. Keep the exact bytes separately so distributed workers and
-- replay use the same input that local dispatch received.
ALTER TABLE runs ADD COLUMN trigger_input BYTEA;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE runs DROP COLUMN trigger_input;
-- +goose StatementEnd

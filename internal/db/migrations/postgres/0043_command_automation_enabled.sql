-- +goose Up
-- +goose StatementBegin

-- Command plans are review data by default. Enabling a plan is a separate,
-- tenant-scoped, optimistic-concurrency mutation performed only after the
-- operator has reviewed the exact immutable version.
ALTER TABLE command_automations
    ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE command_automations DROP COLUMN enabled;
-- +goose StatementEnd

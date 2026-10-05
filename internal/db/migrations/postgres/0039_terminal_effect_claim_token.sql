-- +goose Up
-- +goose StatementBegin

-- Each terminal-effect claim gets a random generation token. Timestamps alone
-- are not unique enough to fence a same-status retry generation.
ALTER TABLE terminal_effects ADD COLUMN claim_token TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE terminal_effects DROP COLUMN IF EXISTS claim_token;
-- +goose StatementEnd

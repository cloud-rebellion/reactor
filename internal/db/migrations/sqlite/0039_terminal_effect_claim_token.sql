-- +goose Up
-- +goose StatementBegin

-- Each terminal-effect claim gets a random generation token. Timestamps are
-- not unique at SQLite millisecond precision, so the token is the authoritative
-- fence for acknowledgement/release after a same-status DLQ retry.
ALTER TABLE terminal_effects ADD COLUMN claim_token TEXT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE terminal_effects DROP COLUMN claim_token;
-- +goose StatementEnd

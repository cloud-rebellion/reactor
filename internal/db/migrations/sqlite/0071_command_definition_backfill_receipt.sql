-- +goose Up
-- +goose StatementBegin
ALTER TABLE command_automation_versions ADD COLUMN definition_canonical_sha256 TEXT
    CHECK (definition_canonical_sha256 IS NULL OR
        (definition_crypto_version = 1 AND length(definition_canonical_sha256) = 64
         AND definition_canonical_sha256 NOT GLOB '*[^0-9a-f]*'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TEMP TABLE _reactor_command_definition_backfill_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO _reactor_command_definition_backfill_down_guard
    SELECT 1 FROM command_automation_versions WHERE definition_canonical_sha256 IS NOT NULL LIMIT 1;
DROP TABLE _reactor_command_definition_backfill_down_guard;
ALTER TABLE command_automation_versions DROP COLUMN definition_canonical_sha256;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin
-- Legacy JSONB rendering can differ byte-for-byte from the normalized
-- definition digest already shown to reviewers. Preserve that digest while a
-- storage-only backfill records the exact sealed bytes in definition_sha256.
ALTER TABLE command_automation_versions ADD COLUMN definition_canonical_sha256 TEXT;
ALTER TABLE command_automation_versions ADD CONSTRAINT command_definition_canonical_sha_check CHECK (
    definition_canonical_sha256 IS NULL OR
    (definition_crypto_version = 1 AND definition_canonical_sha256 ~ '^[0-9a-f]{64}$')
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM command_automation_versions WHERE definition_canonical_sha256 IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back command definition backfill receipts while backfilled rows exist';
    END IF;
END $$;
ALTER TABLE command_automation_versions DROP CONSTRAINT command_definition_canonical_sha_check;
ALTER TABLE command_automation_versions DROP COLUMN definition_canonical_sha256;
-- +goose StatementEnd

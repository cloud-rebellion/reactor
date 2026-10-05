-- +goose Up
-- +goose StatementBegin
ALTER TABLE workflow_versions ADD COLUMN source_manifest_sha256 TEXT
    CHECK (source_manifest_sha256 IS NULL OR
        (length(source_manifest_sha256) = 64 AND source_manifest_sha256 NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE workflow_versions ADD COLUMN source_proof_version INTEGER NOT NULL DEFAULT 2
    CHECK (source_proof_version IN (1, 2));
UPDATE workflow_versions SET source_proof_version = 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE workflow_versions DROP COLUMN source_manifest_sha256;
ALTER TABLE workflow_versions DROP COLUMN source_proof_version;
-- +goose StatementEnd

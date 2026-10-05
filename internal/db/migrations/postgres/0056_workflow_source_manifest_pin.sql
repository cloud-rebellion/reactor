-- +goose Up
-- +goose StatementBegin
-- New authored versions pin the exact retained source manifest bytes. Existing
-- rows stay NULL: their manifest was not bound at publication time, so a
-- migration cannot reconstruct trustworthy historical source proof.
ALTER TABLE workflow_versions ADD COLUMN source_manifest_sha256 TEXT
    CHECK (source_manifest_sha256 IS NULL OR source_manifest_sha256 ~ '^[0-9a-f]{64}$');
-- Existing versions retain their publication-time policy. New rows default to
-- 2, so a newly registered null-pin artifact cannot claim legacy exemption.
ALTER TABLE workflow_versions ADD COLUMN source_proof_version INTEGER NOT NULL DEFAULT 2
    CHECK (source_proof_version IN (1, 2));
UPDATE workflow_versions SET source_proof_version = 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE workflow_versions DROP COLUMN IF EXISTS source_manifest_sha256;
ALTER TABLE workflow_versions DROP COLUMN IF EXISTS source_proof_version;
-- +goose StatementEnd

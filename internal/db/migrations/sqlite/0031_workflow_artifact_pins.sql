-- +goose Up
-- +goose StatementBegin

-- See the PostgreSQL mirror for the safety rationale. Nullable preserves the
-- audit history without pretending legacy mutable binaries were immutable.
ALTER TABLE workflow_versions ADD COLUMN artifact_sha256 TEXT
    CHECK (artifact_sha256 IS NULL OR
        (length(artifact_sha256) = 64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE runs ADD COLUMN workflow_artifact_sha256 TEXT
    CHECK (workflow_artifact_sha256 IS NULL OR
        (length(workflow_artifact_sha256) = 64 AND workflow_artifact_sha256 NOT GLOB '*[^0-9a-f]*'));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE runs DROP COLUMN workflow_artifact_sha256;
ALTER TABLE workflow_versions DROP COLUMN artifact_sha256;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- A numeric workflow version is not an executable identity. Keep the immutable
-- artifact digest on both the historical version row and each run so a queued,
-- resumed, or redriven run can resolve the exact bytes it was dispatched with.
ALTER TABLE workflow_versions ADD COLUMN artifact_sha256 TEXT
    CHECK (artifact_sha256 IS NULL OR artifact_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE runs ADD COLUMN workflow_artifact_sha256 TEXT
    CHECK (workflow_artifact_sha256 IS NULL OR workflow_artifact_sha256 ~ '^[0-9a-f]{64}$');

-- Existing rows intentionally remain NULL. There is no trustworthy way for a
-- database migration to prove which mutable on-disk binary an old run used.
-- They fail closed until workflows are rebuilt/re-registered; old nonterminal
-- runs require an operator decision rather than silently using current code.

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE runs DROP COLUMN IF EXISTS workflow_artifact_sha256;
ALTER TABLE workflow_versions DROP COLUMN IF EXISTS artifact_sha256;
-- +goose StatementEnd

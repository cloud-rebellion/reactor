-- +goose Up
-- +goose StatementBegin
-- A publisher copies only immutable, journal-pinned workflow bytes to the
-- worker artifact tree. No filesystem path, source bytes, or secret is queued.
CREATE TABLE artifact_publications (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
    workflow_id        TEXT NOT NULL,
    version            INTEGER NOT NULL CHECK (version > 0),
    artifact_sha256    TEXT NOT NULL CHECK (length(artifact_sha256) = 64),
    status             TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'published', 'failed')),
    attempts           INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
    claim_token        TEXT,
    claim_until        TEXT,
    next_attempt_at    TEXT NOT NULL,
    requested_at       TEXT NOT NULL,
    published_at       TEXT,
    last_failure_code  TEXT,
    FOREIGN KEY (workflow_id, version) REFERENCES workflow_versions(workflow_id, version) ON DELETE CASCADE,
    UNIQUE (workflow_id, version)
);
CREATE INDEX artifact_publications_claim_idx
    ON artifact_publications (status, next_attempt_at, claim_until, requested_at);
CREATE INDEX artifact_publications_tenant_idx
    ON artifact_publications (tenant_id, requested_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS artifact_publications_tenant_idx;
DROP INDEX IF EXISTS artifact_publications_claim_idx;
DROP TABLE IF EXISTS artifact_publications;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- Append-only control-plane receipts for MCP mutations. Request payloads are
-- intentionally not stored: they may contain workflow data or operator input.
CREATE TABLE mcp_audit (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    actor_id   TEXT NOT NULL DEFAULT '',
    tool_name  TEXT NOT NULL,
    outcome    TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    target     TEXT NOT NULL DEFAULT '',
    detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
    at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX mcp_audit_tenant_at_idx ON mcp_audit(tenant_id, at DESC, id DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS mcp_audit_tenant_at_idx;
DROP TABLE IF EXISTS mcp_audit;
-- +goose StatementEnd

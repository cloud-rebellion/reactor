-- +goose Up
-- +goose StatementBegin

CREATE INDEX runs_tenant_started_analytics_idx
    ON runs(tenant_id, started_at)
    WHERE started_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runs_tenant_started_analytics_idx;
-- +goose StatementEnd

-- +goose Up
-- +goose StatementBegin

-- The seven-day tenant dashboard filters by owner and start time. The older
-- (tenant_id, status) and (status, started_at) indexes cannot bound both
-- predicates, so retained history otherwise dominates this read.
CREATE INDEX runs_tenant_started_analytics_idx
    ON runs(tenant_id, started_at)
    WHERE started_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS runs_tenant_started_analytics_idx;
-- +goose StatementEnd

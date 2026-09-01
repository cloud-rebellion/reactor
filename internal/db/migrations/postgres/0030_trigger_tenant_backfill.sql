-- +goose Up
-- +goose StatementBegin

-- Trigger ownership is derived from the workflow it dispatches. Older create
-- paths omitted tenant_id and silently took the schema default, even when the
-- workflow belonged to another tenant.
UPDATE triggers
SET tenant_id = (
    SELECT workflows.tenant_id
    FROM workflows
    WHERE workflows.id = triggers.workflow_id
)
WHERE EXISTS (
    SELECT 1 FROM workflows WHERE workflows.id = triggers.workflow_id
)
AND tenant_id <> (
    SELECT workflows.tenant_id
    FROM workflows
    WHERE workflows.id = triggers.workflow_id
);

-- Dashboard-generated webhook credentials are dedicated to one trigger and
-- carry an explicit service/provider marker plus name=id. Backfill only that
-- unambiguous one-to-one shape. Shared credentials and operator-managed rows
-- are intentionally left untouched for an operator to reconcile explicitly.
UPDATE credentials
SET tenant_id = (
    SELECT workflows.tenant_id
    FROM triggers
    JOIN workflows ON workflows.id = triggers.workflow_id
    WHERE triggers.kind = 'webhook'
      AND triggers.secret_id = credentials.id
    LIMIT 1
)
WHERE service = 'reactor-webhook'
  AND provider = 'shared-secret'
  AND name = id
  AND deleted_at IS NULL
  AND 1 = (
      SELECT COUNT(*)
      FROM triggers
      WHERE triggers.kind = 'webhook'
        AND triggers.secret_id = credentials.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM credentials AS existing
      WHERE existing.id <> credentials.id
        AND existing.name = credentials.name
        AND existing.tenant_id = (
            SELECT workflows.tenant_id
            FROM triggers
            JOIN workflows ON workflows.id = triggers.workflow_id
            WHERE triggers.kind = 'webhook'
              AND triggers.secret_id = credentials.id
            LIMIT 1
        )
  )
  AND tenant_id <> (
      SELECT workflows.tenant_id
      FROM triggers
      JOIN workflows ON workflows.id = triggers.workflow_id
      WHERE triggers.kind = 'webhook'
        AND triggers.secret_id = credentials.id
      LIMIT 1
  );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Ownership correction is intentionally irreversible: reverting it would
-- recreate cross-tenant metadata rather than restore meaningful prior state.
SELECT 1;
-- +goose StatementEnd

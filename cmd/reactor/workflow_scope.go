package main

import (
	"context"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// defaultTenantWorkflowID is the only unqualified-slug lookup used by CLI/MCP
// execution surfaces. Slugs are unique per tenant, not globally; these tools
// carry no tenant parameter and therefore must resolve the same DefaultTenant
// their workflow registration commands write to.
func defaultTenantWorkflowID(ctx context.Context, j *journal.Journal, slug string) (string, error) {
	return j.WorkflowIDBySlugInTenant(ctx, slug, journal.DefaultTenant)
}

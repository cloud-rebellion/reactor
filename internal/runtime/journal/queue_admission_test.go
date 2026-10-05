package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
)

// The fair candidate query is only a scheduling hint. A tenant may fill its
// last slot or be disabled after that query and before the locked claim set is
// admitted. Exercise that second boundary independently of the query plan.
func TestLockedTenantClaimsRecheckCapacityAndKeepFairOrder(t *testing.T) {
	t.Parallel()
	j, cleanup := newTestJournal(t)
	defer cleanup()
	ctx := context.Background()
	for _, tenantID := range []string{"full", "one-slot", "disabled", "unregistered"} {
		mkWorkflowTenant(t, j, ctx, "wf_"+tenantID, tenantID)
	}
	for _, tenant := range []Tenant{
		{TenantID: "full", MaxConcurrentRuns: 1},
		{TenantID: "one-slot", MaxConcurrentRuns: 2},
		{TenantID: "disabled", Disabled: true},
	} {
		if err := j.UpsertTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenantID := range []string{"full", "one-slot"} {
		if err := j.CreateRun(ctx, "running_"+tenantID, "wf_"+tenantID, "manual", json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	locked := []string{"full_0", "one_0", "disabled_0", "unregistered_0", "one_1", "unregistered_1"}
	tenantByRun := map[string]string{
		"full_0": "full", "one_0": "one-slot", "disabled_0": "disabled",
		"unregistered_0": "unregistered", "one_1": "one-slot", "unregistered_1": "unregistered",
	}
	tx, err := j.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	got, err := j.admitLockedTenantClaimsTx(ctx, tx, locked, tenantByRun, 3)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one_0", "unregistered_0", "unregistered_1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("locked tenant admission = %v, want %v", got, want)
	}
}

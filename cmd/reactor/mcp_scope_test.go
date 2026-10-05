package main

import (
	"testing"

	"github.com/bright-interaction/reactor/internal/auth"
)

func TestMCPStdioWriteScopesPreserveExplicitLeastPrivilege(t *testing.T) {
	t.Parallel()

	scopes := mcpStdioWriteScopes(false, true, false, false, false, false, false, false, false, false)
	if !scopes.Authoring || scopes.Triggers || scopes.Notifications || scopes.Dispatch || scopes.Secrets || scopes.Knowledge || scopes.Diagnostics || scopes.DataExport || scopes.DataLifecycle {
		t.Fatalf("authoring-only scopes = %+v", scopes)
	}

	lifecycle := mcpStdioWriteScopes(false, false, false, false, false, false, false, false, false, true)
	if !lifecycle.DataLifecycle || lifecycle.DataExport || lifecycle.Authoring || lifecycle.Dispatch {
		t.Fatalf("data-lifecycle-only scopes = %+v", lifecycle)
	}
	export := mcpStdioWriteScopes(false, false, false, false, false, false, false, false, true, false)
	if !export.DataExport || export.DataLifecycle || export.Authoring || export.Dispatch {
		t.Fatalf("data-export-only scopes = %+v", export)
	}
}

func TestMCPStdioAllowWriteEnablesEveryWriteScope(t *testing.T) {
	t.Parallel()

	scopes := mcpStdioWriteScopes(true, false, false, false, false, false, false, false, false, false)
	if !scopes.Authoring || !scopes.Triggers || !scopes.Notifications || !scopes.Dispatch || !scopes.Secrets || !scopes.Knowledge || !scopes.Diagnostics || !scopes.DataExport || !scopes.DataLifecycle {
		t.Fatalf("--allow-write scopes = %+v; compatibility alias must include data lifecycle", scopes)
	}
}

func TestDaemonCommandExecutionCapabilitiesOnlyProjectAuthenticatedSudo(t *testing.T) {
	t.Parallel()

	admin := commandExecutionCapabilitiesFor(auth.User{ID: "admin", Role: auth.RoleAdmin}, true, true)
	if !admin.AdminAuthorized || !admin.StepUpAuthorized {
		t.Fatalf("admin sudo capabilities = %+v, want only auth facts true", admin)
	}
	if admin.FeatureEnabled || admin.SingleTenant || admin.SandboxProfileReady || admin.VaultBoundaryReady || admin.CredentialsSupported || admin.OutputLimitsReady || admin.AuditReady {
		t.Fatalf("unimplemented command gates opened: %+v", admin)
	}

	member := commandExecutionCapabilitiesFor(auth.User{ID: "member", Role: auth.RoleMember}, true, true)
	if member.AdminAuthorized || !member.StepUpAuthorized {
		t.Fatalf("member sudo capabilities = %+v, want admin false and context step-up true", member)
	}
	unauthenticated := commandExecutionCapabilitiesFor(auth.User{ID: "admin", Role: auth.RoleAdmin}, false, true)
	if unauthenticated.AdminAuthorized || unauthenticated.StepUpAuthorized {
		t.Fatalf("unauthenticated context opened command authority: %+v", unauthenticated)
	}
}

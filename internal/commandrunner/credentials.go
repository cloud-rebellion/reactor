package commandrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/bright-interaction/reactor/internal/vault"
)

// VaultReader is the narrow value surface required by the command
// materializer. It deliberately returns the vault's redacting Secret type;
// only this package's short-lived materialization path calls Reveal.
type VaultReader interface {
	Get(context.Context, string) (*vault.Secret, error)
}

// SecretTenantLookup keeps the vault value lookup behind the journal's
// tenant-aware owner check. A vault Store alone has no tenant predicate.
type SecretTenantLookup interface {
	SecretTenant(context.Context, string) (string, error)
}

// OAuthTokenResolver is the tenant-scoped raw-token boundary. The policy check
// lets preflight reject broker-only connections before a run is created;
// RawToken must enforce that policy again against the current connection when
// materializing a step, after any token refresh. OAuth references remain
// denied when no resolver is configured.
type OAuthTokenResolver interface {
	RawTokenAllowed(context.Context, string, string) (bool, error)
	RawToken(context.Context, string, string) (string, error)
}

// VaultCredentialMaterializer implements the command credential boundary for
// regular vault credentials and, when explicitly wired, oauth:<connection>
// references. Every reference must belong to the active tenant and have a
// command-specific grant. No value is returned until both checks pass.
type VaultCredentialMaterializer struct {
	Grants      CommandGrantJournal
	Tenants     SecretTenantLookup
	Vault       VaultReader
	OAuthTokens OAuthTokenResolver
}

// Supports reports whether this materializer has a resolver for a reference
// namespace. It does not inspect ownership or grants; those checks happen at
// Materialize time immediately before execution.
func (m VaultCredentialMaterializer) Supports(id string) bool {
	if strings.HasPrefix(id, "oauth:") {
		return m.OAuthTokens != nil
	}
	return m.Vault != nil
}

// SupportsForTenant is the non-secret resolver check used by MCP readiness.
// A configured OAuth resolver alone is not enough: broker-only connections
// cannot be materialized into command environments, even with a grant. The
// actual materializer repeats this policy after claim, before token release.
func (m VaultCredentialMaterializer) SupportsForTenant(ctx context.Context, tenantID, id string) bool {
	if !m.Supports(id) {
		return false
	}
	connectionID, isOAuth := strings.CutPrefix(id, "oauth:")
	if !isOAuth {
		return true
	}
	if connectionID == "" || strings.TrimSpace(tenantID) == "" {
		return false
	}
	allowed, err := m.OAuthTokens.RawTokenAllowed(ctx, connectionID, tenantID)
	return err == nil && allowed
}

// Check performs the non-secret half of Materialize. It is intentionally
// separate so Runner can reject a missing tenant row, command grant, or value
// resolver before creating a durable run. It never calls Reveal or returns a
// credential value.
func (m VaultCredentialMaterializer) Check(ctx context.Context, tenantID, automationID string, version int, credentialIDs []string) error {
	tenantID = strings.TrimSpace(tenantID)
	automationID = strings.TrimSpace(automationID)
	if tenantID == "" || automationID == "" || version < 1 || len(credentialIDs) == 0 {
		return ErrCredentialBoundary
	}
	if m.Grants == nil || m.Tenants == nil {
		return ErrCredentialBoundary
	}
	seen := make(map[string]struct{}, len(credentialIDs))
	for _, rawID := range credentialIDs {
		id := strings.TrimSpace(rawID)
		if id == "" || id != rawID || len(id) > 256 || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return errors.New("invalid credential reference")
		}
		if _, exists := seen[id]; exists {
			return errors.New("duplicate credential reference")
		}
		seen[id] = struct{}{}
		owner, ownerErr := m.Tenants.SecretTenant(ctx, id)
		if ownerErr != nil || strings.TrimSpace(owner) != tenantID {
			return fmt.Errorf("credential %q cannot be resolved for tenant", id)
		}
		granted, grantErr := m.Grants.HasCommandGrant(ctx, tenantID, automationID, id)
		if grantErr != nil || !granted {
			return fmt.Errorf("credential %q is not explicitly granted", id)
		}
		if strings.HasPrefix(id, "oauth:") {
			connectionID := strings.TrimPrefix(id, "oauth:")
			if connectionID == "" || m.OAuthTokens == nil {
				return fmt.Errorf("credential %q has no OAuth resolver", id)
			}
			allowed, policyErr := m.OAuthTokens.RawTokenAllowed(ctx, connectionID, tenantID)
			if policyErr != nil || !allowed {
				return fmt.Errorf("credential %q requires a host-brokered connector", id)
			}
		} else if m.Vault == nil {
			return fmt.Errorf("credential %q has no vault resolver", id)
		}
	}
	return nil
}

// Materialize resolves one step's references after the runner has admitted
// the exact version and claimed its lease. Any partial materialization is
// cleared before an error is returned.
func (m VaultCredentialMaterializer) Materialize(ctx context.Context, tenantID, automationID string, version, stepSeq int, credentialIDs []string) (out CredentialMaterialization, err error) {
	tenantID = strings.TrimSpace(tenantID)
	automationID = strings.TrimSpace(automationID)
	if tenantID == "" || automationID == "" || version < 1 || stepSeq < 1 || len(credentialIDs) == 0 {
		return out, ErrCredentialBoundary
	}
	if m.Grants == nil || m.Tenants == nil {
		return out, ErrCredentialBoundary
	}
	defer func() {
		if err != nil {
			out.Clear()
		}
	}()
	seen := make(map[string]struct{}, len(credentialIDs))
	for _, rawID := range credentialIDs {
		id := strings.TrimSpace(rawID)
		if id == "" || id != rawID || len(id) > 256 || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return out, errors.New("invalid credential reference")
		}
		if _, exists := seen[id]; exists {
			return out, errors.New("duplicate credential reference")
		}
		seen[id] = struct{}{}
		owner, ownerErr := m.Tenants.SecretTenant(ctx, id)
		if ownerErr != nil || strings.TrimSpace(owner) != tenantID {
			if ownerErr != nil {
				return out, fmt.Errorf("credential %q cannot be resolved for tenant", id)
			}
			return out, fmt.Errorf("credential %q belongs to another tenant", id)
		}
		granted, grantErr := m.Grants.HasCommandGrant(ctx, tenantID, automationID, id)
		if grantErr != nil {
			return out, fmt.Errorf("credential %q grant lookup failed", id)
		}
		if !granted {
			return out, fmt.Errorf("credential %q is not explicitly granted", id)
		}

		value, valueErr := m.resolveValue(ctx, tenantID, id)
		if valueErr != nil {
			return out, valueErr
		}
		tooLarge := len(value) > vault.MaxSecretBytes
		if len(value) == 0 || tooLarge || bytes.IndexByte(value, 0) >= 0 {
			for i := range value {
				value[i] = 0
			}
			if tooLarge {
				return out, fmt.Errorf("credential %q exceeds the maximum supported size", id)
			}
			return out, fmt.Errorf("credential %q is empty or contains an unsupported NUL byte", id)
		}
		out.Bindings = append(out.Bindings, CredentialBinding{
			CredentialID: id,
			Environment:  CredentialEnvironmentName(id),
			Value:        value,
		})
	}
	return out, nil
}

func (m VaultCredentialMaterializer) resolveValue(ctx context.Context, tenantID, id string) ([]byte, error) {
	if connectionID, isOAuth := strings.CutPrefix(id, "oauth:"); isOAuth {
		if m.OAuthTokens == nil || strings.TrimSpace(connectionID) == "" {
			return nil, fmt.Errorf("credential %q has no OAuth resolver", id)
		}
		allowed, policyErr := m.OAuthTokens.RawTokenAllowed(ctx, connectionID, tenantID)
		if policyErr != nil || !allowed {
			return nil, fmt.Errorf("credential %q requires a host-brokered connector", id)
		}
		token, err := m.OAuthTokens.RawToken(ctx, connectionID, tenantID)
		if err != nil || token == "" {
			return nil, fmt.Errorf("credential %q OAuth resolution failed", id)
		}
		return []byte(token), nil
	}
	if m.Vault == nil {
		return nil, fmt.Errorf("credential %q has no vault resolver", id)
	}
	secret, err := m.Vault.Get(ctx, id)
	if err != nil || secret == nil {
		return nil, fmt.Errorf("credential %q vault resolution failed", id)
	}
	value := append([]byte(nil), secret.Reveal()...)
	return value, nil
}

// CredentialEnvironmentName maps a credential id to a stable, non-identifying
// environment name. Hashing avoids exposing service names in process metadata
// while giving command authors a deterministic reference to use.
func CredentialEnvironmentName(id string) string {
	sum := sha256.Sum256([]byte("reactor-command-credential-v1\x00" + id))
	return "REACTOR_CREDENTIAL_" + strings.ToUpper(hex.EncodeToString(sum[:16]))
}

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// stubRotator implements CredentialRotator with programmable capabilities.
type stubRotator struct {
	canAuto      bool
	mintsLocally bool
	unknown      bool
	rotateCalls  int
}

func (s *stubRotator) RotateOne(_ context.Context, _ string) error {
	s.rotateCalls++
	return nil
}

func (s *stubRotator) ProviderCapabilities(_ string) (bool, bool, error) {
	if s.unknown {
		return false, false, errors.New("unknown provider")
	}
	return s.canAuto, s.mintsLocally, nil
}

func newGuardServer(rot CredentialRotator) *Server {
	return &Server{
		Rotator: rot,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// TestCredentialCreateRefusesDestructiveProvider pins the fix for the worst
// product defect in the 2026-07-25 audit. shared-secret was the FIRST <option>
// and therefore the default, and it MINTS a new random value locally. An
// operator added a real Stripe key with the select untouched, clicked "Rotate
// now", and the sk_live_ key was overwritten with random hex while the audit
// trail recorded rotate.success and Stripe still held the old key. Payments
// break silently and the original is unrecoverable.
//
// The refusal happens before the repo or vault is touched, so an unwired Server
// is sufficient here.
func TestRotationGuard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		rot        *stubRotator
		autoRotate bool
		ackReplace bool
		wantReason string // substring; "" means the combination must be allowed
	}{
		{
			// The Stripe case: value-replacing provider, no acknowledgement.
			name:       "destructive provider without acknowledgement is refused",
			rot:        &stubRotator{canAuto: true, mintsLocally: true},
			wantReason: "REPLACES the stored value",
		},
		{
			// Not a wall: an HMAC signing key Reactor itself issues is a
			// legitimate use of shared-secret.
			name:       "destructive provider with acknowledgement is allowed",
			rot:        &stubRotator{canAuto: true, mintsLocally: true},
			ackReplace: true,
		},
		{
			name:       "auto-rotate on a reminder-only provider is refused",
			rot:        &stubRotator{canAuto: false},
			autoRotate: true,
			wantReason: "cannot rotate automatically",
		},
		{
			name: "reminder-only provider without auto-rotate is allowed",
			rot:  &stubRotator{canAuto: false},
		},
		{
			name: "roll-at-source provider is allowed",
			rot:  &stubRotator{canAuto: true},
		},
		{
			name:       "auto-rotate on a roll-at-source provider is allowed",
			rot:        &stubRotator{canAuto: true},
			autoRotate: true,
		},
		{
			name:       "unknown provider is refused",
			rot:        &stubRotator{unknown: true},
			wantReason: "unknown provider",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newGuardServer(tc.rot)
			got := s.rotationGuard("p", tc.autoRotate, tc.ackReplace)
			if tc.wantReason == "" {
				if got != "" {
					t.Fatalf("combination should be allowed, got refusal: %s", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantReason) {
				t.Fatalf("refusal = %q, want it to mention %q", got, tc.wantReason)
			}
		})
	}
}

// TestRotationGuardIsInertWhenRotationUnwired keeps a read-only deployment
// (no Rotator) from being unable to add credentials at all.
func TestRotationGuardIsInertWhenRotationUnwired(t *testing.T) {
	t.Parallel()
	s := newGuardServer(nil)
	if got := s.rotationGuard("shared-secret", true, false); got != "" {
		t.Fatalf("guard should be inert without a Rotator, got: %s", got)
	}
}

// TestCredentialNewFormDefaultsToManual pins the ordering. The default is
// whichever <option> comes first, and a destructive default is how the Stripe
// key got overwritten. manual is correct for every externally issued API key,
// which is what the ~40-service preset catalog is full of.
func TestCredentialNewFormDefaultsToManual(t *testing.T) {
	t.Parallel()
	html := credentialNewBody("", nil, "")
	i := strings.Index(html, `<option value="manual"`)
	if i < 0 {
		t.Fatal("manual option missing")
	}
	for _, other := range []string{"shared-secret", "cloudflare", "aws-iam"} {
		j := strings.Index(html, `<option value="`+other+`"`)
		if j >= 0 && j < i {
			t.Fatalf("%q precedes manual, making it the default; a destructive default is the bug", other)
		}
	}
	if !strings.Contains(html, `name="confirm_replace"`) {
		t.Fatal("the acknowledgement checkbox for value-replacing providers is missing")
	}
}

// TestRotateHintDescribesTheActualEffect pins the copy next to the button. The
// hint used to claim it "runs the provider's mint -> deliver -> audit pipeline"
// for every provider, including reminder-only ones where nothing happens.
func TestRotateHintDescribesTheActualEffect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		rot      *stubRotator
		want     string
		mintsLoc bool
	}{
		{"reminder only", &stubRotator{canAuto: false}, "records a reminder only", false},
		{"local mint", &stubRotator{canAuto: true, mintsLocally: true}, "NEW RANDOM secret", true},
		{"rolls at source", &stubRotator{canAuto: true}, "rolls the credential at its source", false},
		{"unknown provider", &stubRotator{unknown: true}, "unknown provider", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newGuardServer(tc.rot)
			hint, mintsLoc := s.rotateHint("p")
			if !strings.Contains(hint, tc.want) {
				t.Fatalf("hint = %q, want it to mention %q", hint, tc.want)
			}
			if mintsLoc != tc.mintsLoc {
				t.Fatalf("mintsLocally = %v, want %v", mintsLoc, tc.mintsLoc)
			}
		})
	}
}

// TestCredentialDetailWarnsBeforeDestructiveRotate closes the loop on the button
// itself: the primary-styled "Rotate now" fired with no confirmation at all.
func TestCredentialDetailWarnsBeforeDestructiveRotate(t *testing.T) {
	t.Parallel()
	c := credentials.Credential{ID: "stripe-key", Name: "stripe-key", Provider: "shared-secret"}

	destructive := credentialDetailBody(c, nil, nil, "",
		rotateView{hint: "generates a NEW RANDOM secret", mintsLocally: true})
	if !strings.Contains(destructive, "data-confirm=") {
		t.Fatal("a value-replacing rotation must be confirmed before it discards the secret")
	}
	if !strings.Contains(destructive, "cannot be recovered") {
		t.Fatal("the confirmation should name the consequence, not just ask 'are you sure'")
	}
	if !strings.Contains(destructive, `name="allow_local_mint"`) || !strings.Contains(destructive, "required") {
		t.Fatal("a value-replacing rotation must require a server-visible acknowledgement")
	}

	safe := credentialDetailBody(c, nil, nil, "",
		rotateView{hint: "rolls the credential at its source", mintsLocally: false})
	if strings.Contains(safe, "data-confirm=\"Provider") {
		t.Fatal("a roll-at-source rotation should not nag; confirmations lose meaning if everything has one")
	}
	if strings.Contains(safe, `name="allow_local_mint"`) {
		t.Fatal("roll-at-source rotation should not show a local-mint acknowledgement")
	}
}

// TestTenantSelectRendersChoiceOnlyWhenThereIsOne keeps the picker from being
// noise on a single-tenant install while still submitting explicit ownership.
func TestTenantSelectRendersChoiceOnlyWhenThereIsOne(t *testing.T) {
	t.Parallel()

	// One tenant: nothing to choose, but the value is still submitted so the
	// create path states ownership rather than leaning on a column default.
	single := tenantSelect([]journal.Tenant{{TenantID: "acme"}}, "acme")
	if strings.Contains(single, "<select") {
		t.Fatalf("a single tenant should not render a picker:\n%s", single)
	}
	if !strings.Contains(single, `name="tenant_id" value="acme"`) {
		t.Fatalf("single-tenant form must still submit the owner:\n%s", single)
	}

	// Two or more: a real picker, defaulted to the viewer's tenant.
	multi := tenantSelect([]journal.Tenant{{TenantID: "acme"}, {TenantID: "globex"}}, "globex")
	if !strings.Contains(multi, `<option value="globex" selected>`) {
		t.Fatalf("picker should preselect the viewer's tenant:\n%s", multi)
	}
	if !strings.Contains(multi, `<option value="acme">`) {
		t.Fatalf("picker missing the other tenant:\n%s", multi)
	}

	// Empty current falls back to the default tenant rather than an empty owner,
	// because "" downstream means "global" and would be a scoping hole.
	empty := tenantSelect(nil, "")
	if !strings.Contains(empty, `value="`+journal.DefaultTenant+`"`) {
		t.Fatalf("empty tenant must fall back to %q:\n%s", journal.DefaultTenant, empty)
	}
}

// TestWorkflowUploadFormOffersTenant closes the workflow half of tenancy. The
// writer accepted a tenant before this, but with no selector an admin (who is
// global, so viewerScope returns "") had no way to say which one, and every
// upload landed in the default tenant regardless.
func TestWorkflowUploadFormOffersTenant(t *testing.T) {
	t.Parallel()
	html := workflowNewBody("", []journal.Tenant{{TenantID: "acme"}, {TenantID: "globex"}}, "acme")
	if !strings.Contains(html, `name="tenant_id"`) {
		t.Fatalf("upload form cannot express ownership:\n%s", html)
	}
	if !strings.Contains(html, `<option value="globex">`) {
		t.Fatal("upload form does not offer every tenant")
	}
	if !strings.Contains(html, `enctype="multipart/form-data"`) {
		t.Fatal("tenant field must live inside the multipart upload form to be submitted with it")
	}
}

// TestRotationTargetsSectionEmptyState makes the gap legible instead of silent.
// Rotation's differentiator is that consumers pick up the new value without a
// restart; with no targets the value is stored and delivered nowhere, and the
// page used to render nothing at all about that.
func TestRotationTargetsSectionEmptyState(t *testing.T) {
	t.Parallel()
	html := rotationTargetsSection(credentials.Credential{ID: "c1", Name: "c1"})

	if !strings.Contains(html, "deliver it nowhere") {
		t.Fatalf("empty state must say a rotation would deliver nowhere, got:\n%s", html)
	}
	if !strings.Contains(html, `action="/credentials/c1/targets"`) {
		t.Fatal("no add-target form: targets would remain reachable only by hand-written SQL")
	}
	// Every implemented delivery kind must be offerable.
	for _, k := range credentials.TargetKinds {
		if !strings.Contains(html, `<option value="`+k.Kind+`"`) {
			t.Fatalf("kind %q is not offered by the add form", k.Kind)
		}
	}
	// The per-kind help uses the same delegated reveal as the channel form, so
	// it must carry the attributes /assets/ui.js looks for.
	if !strings.Contains(html, `data-reveal-prefix="target-help-"`) {
		t.Fatal("kind select is missing data-reveal-prefix, so the per-kind help never reveals")
	}
	if got := strings.Count(html, "js-reveal-target"); got != len(credentials.TargetKinds) {
		t.Fatalf("js-reveal-target count = %d, want %d (one help block per kind)", got, len(credentials.TargetKinds))
	}
}

// TestRotationTargetsSectionListsTargets covers the populated state, including
// the confirmation on removal (silently dropping a delivery target means a
// future rotation quietly stops reaching a consumer).
func TestRotationTargetsSectionListsTargets(t *testing.T) {
	t.Parallel()
	c := credentials.Credential{
		ID:   "c1",
		Name: "c1",
		RotationTargets: []credentials.Target{
			{Kind: "webhook", URL: "https://a/hook", KeyName: "API_KEY", SecretID: "cred_hmac", GraceSeconds: 30},
		},
	}
	html := rotationTargetsSection(c)

	if strings.Contains(html, "deliver it nowhere") {
		t.Fatal("empty-state warning shown despite a configured target")
	}
	for _, want := range []string{"webhook", "https://a/hook", "API_KEY", "cred_hmac", "30s"} {
		if !strings.Contains(html, want) {
			t.Fatalf("target row missing %q:\n%s", want, html)
		}
	}
	if !strings.Contains(html, `action="/credentials/c1/targets/0/delete"`) {
		t.Fatal("no remove control for the target")
	}
	if !strings.Contains(html, "data-confirm=") {
		t.Fatal("removing a delivery target should be confirmed")
	}
	if !strings.Contains(html, "rotate.delivery_success") {
		t.Fatal("operators need a pointer to where per-target delivery results are recorded")
	}
}

// TestRotationTargetsSectionEscapes keeps an operator-supplied URL from breaking
// out of the attributes it lands in.
func TestRotationTargetsSectionEscapes(t *testing.T) {
	t.Parallel()
	c := credentials.Credential{
		ID:              "c1",
		RotationTargets: []credentials.Target{{Kind: `w"><img src=x onerror=alert(1)>`, URL: "https://a"}},
	}
	html := rotationTargetsSection(c)
	if strings.Contains(html, `<img src=x`) {
		t.Fatalf("target kind broke out of its context:\n%s", html)
	}
}

// TestCredentialDetailShowsRotateOutcome pins the flash. "Rotate now" used to
// 303 back with NO message, so on its most common configuration (manual, which
// the preset script selects for every catalog API-key service) the product's
// headline button did nothing observable and an operator could not tell that
// apart from a real rotation.
func TestCredentialDetailShowsRotateOutcome(t *testing.T) {
	t.Parallel()
	const msg = "Recorded a rotation reminder."
	html := credentialDetailBody(credentials.Credential{ID: "c", Name: "c", Provider: "manual"},
		nil, nil, msg, rotateView{hint: "records a reminder only"})
	if !strings.Contains(html, msg) {
		t.Fatal("the rotation outcome must be shown to the operator, not only written to the audit trail")
	}
}

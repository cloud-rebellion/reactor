package rotators

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/vault"
)

// Runner drives the rotation pipeline: scan credentials needing
// rotation, mint new values via the Provider registry, persist through
// vault.Store, deliver to each rotation target, and audit every step.
//
// One Runner per Reactor process. Tick is exposed so tests can drive
// the runner step-by-step without spinning the goroutine; production
// uses Run() which loops on TickInterval.
type Runner struct {
	Repo  *credentials.Repo
	Vault *vault.Store
	Log   *slog.Logger

	// TickInterval defaults to one hour. Smaller values are accepted in
	// tests; production rotates on the order of days so hourly is
	// plenty.
	TickInterval time.Duration

	// Now overrides the clock for deterministic tests.
	Now func() time.Time

	// Concurrency caps simultaneous rotations across credentials per
	// tick. Default 4. Prevents a misconfigured cron from rate-limiting
	// every cloud provider at once.
	Concurrency int

	once sync.Once
	stop chan struct{}
}

// RotateOneWithLocalMintAck is the explicit acknowledgement path for a
// provider that generates a replacement value inside Reactor. It is intended
// for an operator-triggered rotation (dashboard or CLI). Scheduled rotations
// use the durable acknowledgement recorded on the credential at creation;
// they never get an implicit approval merely because auto_rotate is enabled.
//
// Keep RotateOne as the compatibility entry point for roll-at-source and
// reminder-only providers. A local minter is accepted there only when its
// credential carries LocalMintAcknowledgementKey, which is what makes a
// scheduler restart safe and prevents a forgotten UI checkbox from becoming a
// destructive rotation.
func (r *Runner) RotateOneWithLocalMintAck(ctx context.Context, credentialID string, acknowledged bool) error {
	return r.rotateOne(ctx, credentialID, acknowledged)
}

// Run blocks, ticking the runner at TickInterval until ctx is cancelled
// or Stop is called.
func (r *Runner) Run(ctx context.Context) error {
	r.applyDefaults()
	t := time.NewTicker(r.TickInterval)
	defer t.Stop()

	if err := r.Tick(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.stop:
			return nil
		case <-t.C:
			if err := r.Tick(ctx); err != nil {
				r.Log.Error("rotators: tick failed", "err", err)
			}
		}
	}
}

// Stop signals Run to return. Idempotent.
func (r *Runner) Stop() {
	r.once.Do(func() {
		if r.stop != nil {
			close(r.stop)
		}
	})
}

// Tick runs one pass: list credentials needing rotation, rotate each.
// Exposed so tests + the manual `reactor vault rotate` CLI can drive
// the runner without spinning the loop.
func (r *Runner) Tick(ctx context.Context) error {
	r.applyDefaults()
	due, err := r.Repo.ListNeedingRotation(ctx, r.Now())
	if err != nil {
		return fmt.Errorf("rotators: list due: %w", err)
	}
	if len(due) == 0 {
		return nil
	}

	sem := make(chan struct{}, r.Concurrency)
	var wg sync.WaitGroup
	for _, c := range due {
		c := c
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					r.Log.Error("rotators: per-credential goroutine panicked",
						"credential_id", c.ID, "name", c.Name,
						"panic", rec, "stack", string(debug.Stack()))
				}
			}()
			if err := r.RotateOne(ctx, c.ID); err != nil {
				r.Log.Error("rotators: rotation failed",
					"credential_id", c.ID, "name", c.Name, "err", err)
			}
		}()
	}
	wg.Wait()
	return nil
}

// RotateOne runs the full mint-deliver-audit pipeline for one credential
// id. Manual CLI triggers and tests call this directly.
//
// Steps:
//  1. Load metadata + provider.
//  2. Audit start.
//  3. Get current plaintext from vault.
//  4. Provider.Rotate -> new value.
//  5. vault.Rotate (encrypt + persist + hot-swap).
//  6. credentials.MarkRotated.
//  7. For each target, Deliver + audit per-target outcome.
//  8. Audit success at the end.
//
// ProviderCapabilities describes what rotating a given provider will actually
// do. The dashboard uses it to state the effect BEFORE the click and to refuse
// two combinations that silently do the wrong thing: a value-replacing provider
// on an externally issued key (which destroys it), and Auto-rotate on a provider
// that can only ever record a reminder.
//
// It lives on Runner so the server package can ask through its narrow
// CredentialRotator interface instead of importing this package, which would
// pull the AWS SigV4 and sealed-box dependencies into read-only deployments.
func (r *Runner) ProviderCapabilities(provider string) (canAutoRotate, mintsValueLocally bool, err error) {
	p, err := Get(provider)
	if err != nil {
		return false, false, err
	}
	return p.CanAutoRotate(), MintsValueLocally(p), nil
}

// On any error: stamp last_rotation_error and audit a failure row,
// return the error to the caller.
func (r *Runner) RotateOne(ctx context.Context, credentialID string) error {
	return r.rotateOne(ctx, credentialID, false)
}

// Initialize prepares the runner's defaults and stop channel before Run is
// launched in a daemon goroutine. The serve lifecycle calls this synchronously
// so an immediate shutdown cannot race Run's lazy stop-channel initialization.
// Run remains safe for existing callers that do not need an explicit startup
// fence.
func (r *Runner) Initialize() {
	if r == nil {
		return
	}
	r.applyDefaults()
}

func (r *Runner) rotateOne(ctx context.Context, credentialID string, explicitLocalMintAck bool) error {
	r.applyDefaults()
	cred, err := r.Repo.Get(ctx, credentialID)
	if err != nil {
		return err
	}

	provider, err := Get(cred.Provider)
	if err != nil {
		_ = r.recordError(ctx, credentialID, "unknown_provider", err)
		return err
	}
	if !provider.CanAutoRotate() {
		// Reminder-only provider: emit an audit row + clear error if the
		// operator has rotated manually since last check, but don't
		// touch the value.
		_ = r.Repo.AppendAudit(ctx, credentials.AuditEntry{
			CredentialID: credentialID,
			Action:       "rotate.reminder",
			ActorKind:    "scheduler",
			Detail:       jsonObject("provider", provider.Name()),
		})
		return nil
	}
	if MintsValueLocally(provider) && !explicitLocalMintAck && !credentials.LocalMintAcknowledged(cred.ProviderMeta) {
		err := errors.New("local-mint provider requires explicit acknowledgement before replacing the stored credential value")
		_ = r.recordError(ctx, credentialID, "local_mint_ack_required", err)
		return fmt.Errorf("provider %q: %w", provider.Name(), err)
	}

	_ = r.Repo.AppendAudit(ctx, credentials.AuditEntry{
		CredentialID: credentialID,
		Action:       "rotate.start",
		ActorKind:    "scheduler",
		Detail:       jsonObject("provider", provider.Name()),
	})

	current, err := r.Vault.Get(ctx, credentialID)
	if err != nil {
		_ = r.recordError(ctx, credentialID, "vault_get", err)
		return fmt.Errorf("vault get: %w", err)
	}
	newValue, err := provider.Rotate(ctx, string(current.Reveal()), cred.ProviderMeta)
	if err != nil {
		_ = r.recordError(ctx, credentialID, "provider_rotate", err)
		return fmt.Errorf("provider rotate: %w", err)
	}
	if newValue == "" {
		err := errors.New("provider returned empty value")
		_ = r.recordError(ctx, credentialID, "empty_value", err)
		return err
	}

	oldValue := string(current.Reveal())
	if err := r.Vault.Rotate(ctx, credentialID, []byte(newValue)); err != nil {
		_ = r.recordError(ctx, credentialID, "vault_rotate", err)
		return fmt.Errorf("vault rotate: %w", err)
	}
	if err := r.Repo.MarkRotated(ctx, credentialID, r.Now()); err != nil {
		// Vault is updated but bookkeeping failed; surface the error so
		// the operator notices and can re-run the audit / interval bump.
		_ = r.recordError(ctx, credentialID, "mark_rotated", err)
		return fmt.Errorf("mark rotated: %w", err)
	}

	// Audit the successful in-vault rotation BEFORE delivery so the
	// audit trail tells the truth even if a target later fails.
	_ = r.Repo.AppendAudit(ctx, credentials.AuditEntry{
		CredentialID: credentialID,
		Action:       "rotate.success",
		ActorKind:    "scheduler",
		Detail:       jsonObject("provider", provider.Name()),
	})

	failures := 0
	for _, t := range cred.RotationTargets {
		res := Deliver(ctx, t, oldValue, newValue, r.Vault)
		if res.Success {
			_ = r.Repo.AppendAudit(ctx, credentials.AuditEntry{
				CredentialID: credentialID,
				Action:       "rotate.delivery_success",
				ActorKind:    "scheduler",
				Detail:       jsonObject("kind", t.Kind, "url", t.URL, "key_name", t.KeyName, "status", fmt.Sprintf("%d", res.Status)),
			})
			continue
		}
		failures++
		_ = r.Repo.AppendAudit(ctx, credentials.AuditEntry{
			CredentialID: credentialID,
			Action:       "rotate.delivery_failure",
			ActorKind:    "scheduler",
			Detail:       jsonObject("kind", t.Kind, "url", t.URL, "key_name", t.KeyName, "error", res.Error),
		})
		r.Log.Warn("rotators: target delivery failed",
			"credential_id", credentialID, "url", t.URL, "err", res.Error)
	}
	if failures > 0 {
		// Stamp last_rotation_error so the dashboard surfaces "X of Y
		// targets failed". Vault and credential record stay current.
		_ = r.Repo.RecordError(ctx, credentialID,
			fmt.Sprintf("%d of %d delivery target(s) failed", failures, len(cred.RotationTargets)))
	}
	return nil
}

func (r *Runner) recordError(ctx context.Context, id, code string, cause error) error {
	if cause == nil {
		return nil
	}
	if err := r.Repo.RecordError(ctx, id, fmt.Sprintf("%s: %s", code, cause.Error())); err != nil {
		r.Log.Warn("rotators: record error", "credential_id", id, "err", err)
	}
	_ = r.Repo.AppendAudit(ctx, credentials.AuditEntry{
		CredentialID: id,
		Action:       "rotate.failure",
		ActorKind:    "scheduler",
		Detail:       jsonObject("code", code, "error", cause.Error()),
	})
	return cause
}

func (r *Runner) applyDefaults() {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.TickInterval == 0 {
		r.TickInterval = time.Hour
	}
	if r.Concurrency == 0 {
		r.Concurrency = 4
	}
	if r.stop == nil {
		r.stop = make(chan struct{})
	}
}

// jsonObject produces a json.RawMessage from string key/value pairs.
// Keeps audit detail succinct without hauling in a struct per event.
func jsonObject(kv ...string) json.RawMessage {
	if len(kv)%2 != 0 {
		return json.RawMessage(`{}`)
	}
	m := make(map[string]string, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	b, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

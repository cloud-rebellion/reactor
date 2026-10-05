// Package runtime is the workflow-side runtime that sits behind the public
// SDK. It implements reactor.Flow by speaking the wire protocol over
// stdin (host -> workflow) + stdout (workflow -> host).
//
// The single-binary design: every AI-generated workflow imports this
// package's Serve() entrypoint. The host's supervisor exec's the binary,
// pipes are wired automatically, the SDK calls (Step, Sleep, AwaitSignal,
// vault.MustGet) translate into wire frames and back. The workflow itself
// holds no DB or vault state.
package runtime

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bright-interaction/reactor/sdk"
	"github.com/bright-interaction/reactor/sdk/blocks"
	"github.com/bright-interaction/reactor/sdk/vault"
	"github.com/bright-interaction/reactor/sdk/wire"
)

// PipeFlow implements reactor.Flow over a JSON-lines pipe to the host.
type PipeFlow struct {
	enc *wire.Encoder
	dec *wire.Decoder
	log *slog.Logger

	nextID atomic.Int64

	// nextSeq is the per-run Step call ordinal (1-based). Program order is
	// what makes replay deterministic, so this counts Step calls, not frames.
	nextSeq atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan wire.Frame // request ID -> reply channel

	runID           atomic.Pointer[string] // set on Hello receipt; read by SignalToken
	signalKey       atomic.Pointer[string] // per-run signing key from Hello; "" = legacy
	observedBlocks  atomic.Bool
	connectorBroker atomic.Bool
	mailBroker      atomic.Bool

	helloOnce sync.Once
	helloCh   chan struct{} // closed once readLoop has processed host's Hello

	writeMu sync.Mutex // serialises writes (one Encoder is not concurrent-safe)
	once    sync.Once
	stopErr atomic.Pointer[error]
	stopCh  chan struct{}
}

// New wires a PipeFlow to the given pipes.
func New(in io.Reader, out io.Writer, log *slog.Logger) *PipeFlow {
	if log == nil {
		log = slog.Default()
	}
	pf := &PipeFlow{
		enc:     wire.NewEncoder(out),
		dec:     wire.NewDecoder(in),
		log:     log,
		pending: map[int64]chan wire.Frame{},
		helloCh: make(chan struct{}),
		stopCh:  make(chan struct{}),
	}
	go pf.readLoop()
	return pf
}

// Hello sends the handshake. Workflow code in Serve() calls this once before
// invoking user Run. The runID is captured so SignalToken(name) can derive
// the deterministic capability without a round-trip.
func (p *PipeFlow) Hello(slug, runID, mode string) error {
	id := runID
	p.runID.Store(&id)
	f, err := wire.Wrap(p.id(), 0, wire.KindHello, wire.Hello{
		Version: wire.Version, WorkflowSlug: slug, RunID: runID, Mode: mode,
	})
	if err != nil {
		return err
	}
	return p.write(f)
}

// SignalToken implements reactor.Flow. The token must match what the
// supervisor computes so workflows can compose the public delivery URL
// (POST /signal/{token}) before AwaitSignal blocks the run. When the host
// delivered a per-run SignalKey in Hello, the token is HMAC(SignalKey, name)
// (unforgeable by anyone who only knows the semi-public runID); otherwise it
// falls back to the legacy runID-only SHA-256. Mirrors supervisor.DeriveSignalToken.
func (p *PipeFlow) SignalToken(name string) string {
	if sk := p.signalKey.Load(); sk != nil && *sk != "" {
		if key, err := hex.DecodeString(*sk); err == nil && len(key) > 0 {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(name))
			return "sig_" + hex.EncodeToString(mac.Sum(nil)[:16])
		}
	}
	rid := p.runID.Load()
	var run string
	if rid != nil {
		run = *rid
	}
	h := sha256.Sum256([]byte(run + ":signal:" + name))
	return "sig_" + hex.EncodeToString(h[:16])
}

// Logger returns a slog.Logger that forwards every log line to the host
// over the pipe. This keeps logs centralised; the workflow process never
// writes its own structured log files.
func (p *PipeFlow) Logger() *slog.Logger {
	return slog.New(&pipeHandler{pf: p, level: slog.LevelInfo, attrs: nil})
}

// Step implements reactor.Flow. The contract:
//  1. Send step_start with input_hash + idempotency_key.
//  2. If host replies replay=true, return cached output (no fn call).
//  3. Else run fn, send step_end with output or error, wait for ack.
//  4. Return.
func (p *PipeFlow) Step(ctx context.Context, name string, opts reactor.StepOpts, fn func(context.Context) (any, error)) (any, error) {
	if name == "" {
		return nil, errors.New("reactor: step name required")
	}

	// Claim this call's ordinal BEFORE any I/O so it reflects program order. It
	// stays FIXED across retries; the attempt number is what varies. The
	// journal key is (run_id, seq, step_name, attempt), so each attempt gets its
	// own auditable row and the replay lookup still finds the succeeded one.
	seq := p.nextSeq.Add(1)
	maxAttempts := durableRetryMax(opts.RetryPolicy)

	for localAttempt := 1; ; localAttempt++ {
		var sr wire.StepReply
		for {
			startID := p.id()
			startBody := wire.StepStart{
				StepName:        name,
				IdempotencyKey:  opts.IdempotencyKey,
				InputHash:       hashOpts(opts),
				Attempt:         localAttempt,
				Seq:             seq,
				DurableAttempts: true,
				MaxAttempts:     maxAttempts,
			}
			startFrame, err := wire.Wrap(startID, 0, wire.KindStepStart, startBody)
			if err != nil {
				return nil, err
			}
			replyCh := p.expect(startID)
			if err := p.write(startFrame); err != nil {
				p.unexpect(startID)
				return nil, err
			}
			var (
				reply wire.Frame
				ok    bool
			)
			select {
			case <-ctx.Done():
				p.unexpect(startID)
				return nil, ctx.Err()
			case reply, ok = <-replyCh:
				if !ok {
					return nil, ErrPipeClosed
				}
			}
			sr = wire.StepReply{}
			if err := wire.Unwrap(reply, &sr); err != nil {
				return nil, fmt.Errorf("step reply: %w", err)
			}
			if sr.RetryWaitMs == 0 {
				break
			}
			if sr.RetryWaitMs < 0 || sr.RetryWaitMs > 31000 {
				return nil, errors.New("reactor: invalid provider retry wait from host")
			}
			timer := time.NewTimer(time.Duration(sr.RetryWaitMs) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		if sr.Replay {
			return decodeOutput(sr.Output)
		}
		if sr.RetryExhausted {
			return nil, ErrRetryBudgetExhausted
		}

		// A wire.v1 host predating durable attempts leaves Attempt at zero;
		// retain the old local counter for rolling compatibility. New hosts own
		// the number and may advance it past one after a worker restart/reap.
		attempt := localAttempt
		if sr.Attempt > 0 {
			attempt = sr.Attempt
		}
		budgetAttempt := localAttempt
		if sr.BudgetAttempt > 0 {
			budgetAttempt = sr.BudgetAttempt
		} else if sr.Attempt > 0 {
			// A transitional host may assign a durable absolute attempt without
			// understanding redrive generations. Initial runs use the same number.
			budgetAttempt = sr.Attempt
		}
		if maxAttempts > 0 && budgetAttempt > maxAttempts {
			// Defense in depth for a mismatched/buggy host: never call the user
			// closure beyond the finite budget advertised in step_start.
			return nil, ErrRetryBudgetExhausted
		}

		// A freshly spawned process has not performed the policy delay that
		// normally follows the prior attempt's step_end. Recompute it before
		// the resumed closure. Provider Retry-After is independently persisted
		// by the host: the RetryWaitMs reply above blocks the attempt claim
		// until that provider deadline, even after a worker crash.
		if localAttempt == 1 && budgetAttempt > 1 && opts.RetryPolicy != nil {
			delay, allowed := opts.RetryPolicy.NextDelay(budgetAttempt - 1)
			if !allowed {
				return nil, ErrRetryBudgetExhausted
			}
			p.log.Warn("step retry after resume",
				"step", name, "attempt", attempt, "budget_attempt", budgetAttempt,
				"delay_ms", delay.Milliseconds())
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		// Not replay: actually run the user closure.
		observer := &stepBlockObserver{flow: p, stepName: name, seq: seq, attempt: attempt}
		observedCtx := blocks.WithAggregateObserver(blocks.WithIterateObserver(
			blocks.WithSplitObserver(blocks.WithJoinObserver(ctx, observer), observer), observer), observer)
		observedCtx = context.WithValue(observedCtx, mailStepContextKey{}, mailStepIdentity{
			name: name, seq: seq, attempt: attempt, idempotencyKey: opts.IdempotencyKey,
		})
		out, fnErr := safeCall(observedCtx, fn, opts.Timeout)

		// Decide BEFORE reporting the outcome, because StepEnd.Retryable is how
		// the host learns whether another attempt is coming. The host treats
		// Retryable=false as terminal and dead-letters the step, so reporting a
		// mere classification there (as this used to) dead-lettered a plain
		// error on its first failure while the configured RetryPolicy was never
		// consulted at all.
		delay, willRetry := retryDecision(opts.RetryPolicy, fnErr, budgetAttempt)

		endBody := wire.StepEnd{
			StepName:        name,
			Attempt:         attempt,
			Seq:             seq,
			DurableAttempts: true,
			Output:          marshalOutput(out, fnErr),
		}
		if fnErr != nil {
			endBody.ErrorText = fnErr.Error()
			endBody.Retryable = willRetry
			if willRetry {
				var hint reactor.RetryAfterHint
				if errors.As(fnErr, &hint) {
					if after, allowed := hint.RetryAfterDelay(); allowed && after > 0 && after <= reactor.MaxAutomaticRetryAfter {
						endBody.RetryAfterMs = int64((after + time.Millisecond - 1) / time.Millisecond)
					}
				}
			}
		}
		endID := p.id()
		endFrame, err := wire.Wrap(endID, 0, wire.KindStepEnd, endBody)
		if err != nil {
			return nil, err
		}
		ackCh := p.expect(endID)
		if err := p.write(endFrame); err != nil {
			p.unexpect(endID)
			return nil, err
		}
		select {
		case <-ctx.Done():
			p.unexpect(endID)
			return nil, ctx.Err()
		case _, ok := <-ackCh:
			if !ok {
				return nil, ErrPipeClosed
			}
		}
		if fnErr == nil {
			return out, nil
		}
		if !willRetry {
			return nil, fnErr
		}
		p.log.Warn("step retry",
			"step", name, "attempt", attempt, "budget_attempt", budgetAttempt,
			"err", fnErr.Error(), "delay_ms", delay.Milliseconds())
		select {
		case <-ctx.Done():
			// A cancelled or deadline-exceeded run must not keep retrying;
			// surface the step's own error, which is the actionable one.
			return nil, fnErr
		case <-time.After(delay):
		}
	}
}

// One recorder exists per Step attempt. All observed block calls share one
// ordinal sequence; a retry receives a new attempt.
type stepBlockObserver struct {
	flow     *PipeFlow
	stepName string
	seq      int64
	attempt  int
	next     atomic.Int64
}

func (o *stepBlockObserver) ObserveJoin(ctx context.Context, value blocks.JoinObservation) error {
	return o.report(ctx, wire.BlockReceipt{
		BlockID: value.BlockID, Kind: "merge", Mode: value.Mode,
		LeftRows: value.LeftRows, RightRows: value.RightRows,
		OutputRows: value.OutputRows, MaxRows: value.MaxRows, Outcome: value.Outcome,
	})
}

func (o *stepBlockObserver) ObserveSplit(ctx context.Context, value blocks.SplitObservation) error {
	input, yes, no := value.InputRows, value.YesRows, value.NoRows
	return o.report(ctx, wire.BlockReceipt{
		BlockID: value.BlockID, Kind: "split", InputRows: &input,
		YesRows: &yes, NoRows: &no, Outcome: "succeeded",
	})
}

func (o *stepBlockObserver) ObserveIterate(ctx context.Context, value blocks.CollectionObservation) error {
	input := value.InputRows
	return o.report(ctx, wire.BlockReceipt{
		BlockID: value.BlockID, Kind: "iterate", InputRows: &input,
		OutputRows: value.OutputRows, Outcome: "succeeded",
	})
}

func (o *stepBlockObserver) ObserveAggregate(ctx context.Context, value blocks.CollectionObservation) error {
	input := value.InputRows
	return o.report(ctx, wire.BlockReceipt{
		BlockID: value.BlockID, Kind: "aggregate", InputRows: &input,
		OutputRows: value.OutputRows, Outcome: "succeeded",
	})
}

func (o *stepBlockObserver) report(ctx context.Context, body wire.BlockReceipt) error {
	if !o.flow.observedBlocks.Load() {
		return errors.New("reactor: host does not support observed blocks")
	}
	ordinal := o.next.Add(1)
	if ordinal < 1 || ordinal > 128 {
		return errors.New("reactor: observed block calls exceed 128 per Step attempt")
	}
	id := o.flow.id()
	body.StepName, body.Seq, body.Attempt, body.CallOrdinal = o.stepName, o.seq, o.attempt, int(ordinal)
	frame, err := wire.Wrap(id, 0, wire.KindBlockReceipt, body)
	if err != nil {
		return err
	}
	replyCh := o.flow.expect(id)
	if err := o.flow.write(frame); err != nil {
		o.flow.unexpect(id)
		return err
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		o.flow.unexpect(id)
		return ctx.Err()
	case <-timer.C:
		o.flow.unexpect(id)
		return errors.New("reactor: observed block receipt timed out")
	case response, ok := <-replyCh:
		if !ok || response.Kind != wire.KindAck {
			return errors.New("reactor: observed block receipt was not accepted")
		}
		return nil
	}
}

// retryDecision returns the backoff before the next attempt and whether one
// should happen. No policy means no retry, which keeps the default single-attempt
// behaviour for steps that never asked for retries.
func retryDecision(policy reactor.RetryPolicy, err error, attempt int) (time.Duration, bool) {
	if err == nil || policy == nil {
		return 0, false
	}
	// Retry anything the author did not explicitly mark Permanent. This matches
	// the in-process flow's rule; the previous check (reactor.IsRetryable)
	// required an explicit Retryable() wrapper, so a plain errors.New never
	// retried and ExpBackoff{Max: 5} produced exactly one attempt.
	if reactor.IsPermanent(err) {
		return 0, false
	}
	delay, retry := policy.NextDelay(attempt)
	if !retry {
		return 0, false
	}
	return reactor.RespectRetryAfter(err, delay)
}

// ErrPipeClosed is returned by Step / Sleep / AwaitSignal / FetchSecret
// when the host has torn down the wire (typically because it issued a
// Cancel and is suspending the run). Workflow code should propagate this
// up so Serve exits cleanly; the host's `suspended` override on the
// supervisor side keeps the run state correct regardless.
var ErrPipeClosed = errors.New("reactor: host pipe closed")

// ErrRetryBudgetExhausted is returned without invoking the step closure when
// the host's durable journal says no attempt remains. The host has already
// terminalized/dead-lettered the interrupted step before sending this verdict.
var ErrRetryBudgetExhausted = errors.New("reactor: durable step retry budget exhausted")

// durableRetryMax returns the total finite budget the host may allocate. A nil
// policy is the default single-attempt contract. A custom unbounded/legacy
// policy returns zero; normal in-process retries still work, but an interrupted
// running attempt fails closed because the host cannot prove another attempt is
// permitted.
func durableRetryMax(policy reactor.RetryPolicy) int {
	if policy == nil {
		return 1
	}
	bounded, ok := policy.(reactor.BoundedRetryPolicy)
	if !ok {
		return 0
	}
	if max := bounded.MaxAttempts(); max > 0 {
		return max
	}
	return 1
}

// Sleep yields to the host. Short sleeps wait synchronously; long sleeps
// are upgraded to suspend-and-resume in week 4 (the host kills the process
// and re-spawns at wake_at; the SDK contract is unchanged).
func (p *PipeFlow) Sleep(ctx context.Context, name string, d time.Duration) error {
	id := p.id()
	// Same counter as Step, so the ordinal is this workflow's position in
	// program order across every durable operation, not per-operation-type.
	seq := p.nextSeq.Add(1)
	until := time.Now().Add(d).Unix()
	f, err := wire.Wrap(id, 0, wire.KindSleep, wire.Sleep{StepName: name, UntilUnix: until, Seq: seq})
	if err != nil {
		return err
	}
	ackCh := p.expect(id)
	if err := p.write(f); err != nil {
		p.unexpect(id)
		return err
	}
	select {
	case <-ctx.Done():
		p.unexpect(id)
		return ctx.Err()
	case _, ok := <-ackCh:
		if !ok {
			return ErrPipeClosed
		}
		return nil
	}
}

// AwaitSignal blocks until the host delivers a signal_deliver frame for the
// matching name, or the timeout elapses.
func (p *PipeFlow) AwaitSignal(ctx context.Context, name string, timeout time.Duration) (reactor.Signal, error) {
	id := p.id()
	seq := p.nextSeq.Add(1)
	body := wire.AwaitSignal{StepName: name, SignalName: name, TimeoutMs: timeout.Milliseconds(), Seq: seq}
	f, err := wire.Wrap(id, 0, wire.KindAwaitSignal, body)
	if err != nil {
		return reactor.Signal{}, err
	}
	replyCh := p.expect(id)
	if err := p.write(f); err != nil {
		p.unexpect(id)
		return reactor.Signal{}, err
	}
	var (
		reply wire.Frame
		ok    bool
	)
	select {
	case <-ctx.Done():
		p.unexpect(id)
		return reactor.Signal{}, ctx.Err()
	case reply, ok = <-replyCh:
		if !ok {
			return reactor.Signal{}, ErrPipeClosed
		}
	}
	var sd wire.SignalDeliver
	if err := wire.Unwrap(reply, &sd); err != nil {
		return reactor.Signal{}, fmt.Errorf("signal: %w", err)
	}
	if sd.Expired {
		return reactor.Signal{}, fmt.Errorf("await %q: %w", name, context.DeadlineExceeded)
	}
	return reactor.Signal{Name: sd.SignalName, Data: []byte(sd.Payload)}, nil
}

// FetchSecret resolves a credential through the host's vault. Used by the
// runtime when binding sdk/vault.Resolver before user code runs.
func (p *PipeFlow) FetchSecret(ctx context.Context, id string) (vault.Secret, error) {
	reqID := p.id()
	f, err := wire.Wrap(reqID, 0, wire.KindSecretFetch, wire.SecretFetch{ID: id})
	if err != nil {
		return nil, err
	}
	replyCh := p.expect(reqID)
	if err := p.write(f); err != nil {
		p.unexpect(reqID)
		return nil, err
	}
	var (
		reply wire.Frame
		ok    bool
	)
	select {
	case <-ctx.Done():
		p.unexpect(reqID)
		return nil, ctx.Err()
	case reply, ok = <-replyCh:
		if !ok {
			return nil, ErrPipeClosed
		}
	}
	var sr wire.SecretReply
	if err := wire.Unwrap(reply, &sr); err != nil {
		return nil, fmt.Errorf("secret reply: %w", err)
	}
	if sr.NotFound {
		return nil, fmt.Errorf("vault: credential %q not found", id)
	}
	return &remoteSecret{value: sr.Value, fingerprint: sr.Fingerprint}, nil
}

// Done signals end-of-pipe to readers. Idempotent.
func (p *PipeFlow) Done() {
	p.once.Do(func() { close(p.stopCh) })
}

// readLoop dispatches incoming host frames into pending reply channels and
// handles unsolicited messages (cancel, signal pushes for not-yet-blocked
// AwaitSignal).
func (p *PipeFlow) readLoop() {
	defer p.drainPending() // wake any blocked Step/Sleep/AwaitSignal on shutdown
	for {
		f, err := p.dec.Decode()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				e := err
				p.stopErr.Store(&e)
			}
			p.Done()
			return
		}
		if f.Reply != 0 {
			p.mu.Lock()
			ch, ok := p.pending[f.Reply]
			if ok {
				delete(p.pending, f.Reply)
			}
			p.mu.Unlock()
			if ok {
				ch <- f
				close(ch)
			}
			continue
		}
		// Unsolicited from host. Cancel is the only kind we handle in v0.
		// Closing pending channels unblocks any in-flight Step / Sleep /
		// AwaitSignal so the workflow exits cleanly instead of pinning.
		if f.Kind == wire.KindCancel {
			p.Done()
			return
		}
		// The host's Hello carries the runID. Capture it so SignalToken
		// can derive the deterministic capability without a round-trip.
		// helloCh is closed exactly once so user code can synchronise
		// against runID availability via WaitHello.
		if f.Kind == wire.KindHello {
			var hello wire.Hello
			if err := wire.Unwrap(f, &hello); err == nil && hello.RunID != "" {
				rid := hello.RunID
				p.runID.Store(&rid)
				sk := hello.SignalKey
				p.signalKey.Store(&sk)
				p.observedBlocks.Store(hello.ObservedBlocks)
				p.connectorBroker.Store(hello.ConnectorBroker)
				p.mailBroker.Store(hello.MailBroker)
			}
			p.helloOnce.Do(func() { close(p.helloCh) })
		}
	}
}

// WaitHello blocks until the host's Hello has been processed (so runID is
// stored) or ctx is cancelled. Serve calls this before invoking user code
// so SignalToken returns a stable token even when called from the very
// first line of the workflow.
func (p *PipeFlow) WaitHello(ctx context.Context) error {
	select {
	case <-p.helloCh:
		return nil
	case <-p.stopCh:
		return ErrPipeClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// drainPending closes every pending reply channel so blocked callers see
// a closed-channel return instead of waiting forever. Step / Sleep /
// AwaitSignal each handle a closed reply channel by treating the reply as
// the zero Frame, which Unwrap turns into a sensible error or empty value.
// In suspend mode the workflow process is supposed to exit; in error
// mode the workflow logs the failure and exits non-zero.
func (p *PipeFlow) drainPending() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, ch := range p.pending {
		close(ch)
		delete(p.pending, id)
	}
}

// expect registers a one-shot channel for the host's reply to id. If the
// pipe is already torn down (host sent Cancel + closed stdin), returns an
// immediately-closed channel so callers don't block forever waiting for a
// reply that will never come.
func (p *PipeFlow) expect(id int64) chan wire.Frame {
	ch := make(chan wire.Frame, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.stopCh:
		close(ch)
	default:
		p.pending[id] = ch
	}
	return ch
}

// unexpect removes a pending entry on early cancellation so the response
// (if it arrives later) doesn't leak through into the next call.
func (p *PipeFlow) unexpect(id int64) {
	p.mu.Lock()
	delete(p.pending, id)
	p.mu.Unlock()
}

func (p *PipeFlow) id() int64 { return p.nextID.Add(1) }

func (p *PipeFlow) write(f wire.Frame) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.enc.Encode(f)
}

// hashOpts builds an input fingerprint that the host can record. It is not
// security-critical (we already have the idempotency key for dedup); it is
// only here so the journal can spot DAG drift between runs.
func hashOpts(opts reactor.StepOpts) string {
	h := sha256.New()
	// InputHash is caller-supplied and should already be an opaque, bounded
	// fingerprint. Hash it together with the options so the wire never carries
	// raw business input while still rejecting a changed closure input on
	// resume. Keep the old serialization when it is empty so a new SDK remains
	// replay-compatible with rows written by older workflow binaries.
	if opts.InputHash == "" {
		_, _ = fmt.Fprintf(h, "%s|%d|%d", opts.IdempotencyKey, int64(opts.Timeout), retryHash(opts.RetryPolicy))
	} else {
		_, _ = fmt.Fprintf(h, "%s|%s|%d|%d", opts.IdempotencyKey, opts.InputHash, int64(opts.Timeout), retryHash(opts.RetryPolicy))
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func retryHash(p reactor.RetryPolicy) int64 {
	if p == nil {
		return 0
	}
	if eb, ok := p.(reactor.ExpBackoff); ok {
		return int64(eb.Max)*1_000_000 + int64(eb.Base/time.Millisecond)
	}
	if bounded, ok := p.(reactor.BoundedRetryPolicy); ok {
		return int64(bounded.MaxAttempts())
	}
	return -1
}

// marshalOutput JSON-encodes the step output, returning nil on error.
func marshalOutput(v any, fnErr error) json.RawMessage {
	if fnErr != nil || v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// decodeOutput is the inverse, used on replay. The runtime cannot re-type
// the cached output without knowing T; the SDK's Step[T] generic wrapper
// does the type assertion. We decode into a typeless interface here and
// let the wrapper pick.
func decodeOutput(out json.RawMessage) (any, error) {
	if len(out) == 0 {
		return nil, nil
	}
	// UseNumber keeps JSON numbers as exact json.Number strings instead of
	// float64. Without it, an int64/uint64 SideEffect/Step output above 2^53
	// (a snowflake ID, time.Now().UnixNano(), a large counter) loses precision
	// on replay, so the replayed value differs from the original run and
	// deterministic replay diverges. coerceTo re-marshals the json.Number back
	// into the caller's T exactly.
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("step replay decode: %w", err)
	}
	return v, nil
}

// safeCall mirrors the InProcFlow's panic-recovery guard so a buggy step
// in compiled-binary mode also lands as a step error rather than a crash.
func safeCall(ctx context.Context, fn func(context.Context) (any, error), timeout time.Duration) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in step: %v", r)
		}
	}()
	if timeout > 0 {
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ctx = c
	}
	return fn(ctx)
}

// remoteSecret implements sdk/vault.Secret with bytes shipped over the pipe.
type remoteSecret struct {
	value       []byte
	fingerprint string
}

// Reveal returns a defensive copy. The remote secret is cached in the
// workflow subprocess for the lifetime of the run; returning its backing
// slice would let one handler mutate the credential seen by later steps.
func (r *remoteSecret) Reveal() []byte      { return append([]byte(nil), r.value...) }
func (r *remoteSecret) Fingerprint() string { return r.fingerprint }
func (r *remoteSecret) String() string      { return "[REDACTED]" }

// The remaining methods redact the secret across every accidental-serialization
// channel a workflow author might hit: json.Marshal (MarshalJSON), fmt %s on a
// text-marshaler / %#v (MarshalText / GoString), and slog (LogValue). Without
// these, logging or JSON-encoding a struct that embeds a fetched secret dumps
// the plaintext bytes into the run log (which is readable via the dashboard and
// the reactor_get_run_logs MCP tool). Mirrors the host-side vault.Secret.
func (r *remoteSecret) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (r *remoteSecret) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
func (r *remoteSecret) GoString() string             { return "[REDACTED]" }
func (r *remoteSecret) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }

// pipeHandler is a slog.Handler that ships every record over the wire
// instead of writing locally.
type pipeHandler struct {
	pf     *PipeFlow
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

func (h *pipeHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *pipeHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{}
	for _, a := range h.attrs {
		addLogAttr(attrs, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		addLogAttr(attrs, a)
		return true
	})
	for i := len(h.groups) - 1; i >= 0; i-- {
		if h.groups[i] == "" {
			continue
		}
		attrs = map[string]any{h.groups[i]: attrs}
	}
	body := wire.Log{Level: r.Level.String(), Msg: r.Message, Attrs: attrs}
	f, err := wire.Wrap(h.pf.id(), 0, wire.KindLog, body)
	if err != nil {
		return err
	}
	return h.pf.write(f)
}

func addLogAttr(dst map[string]any, attr slog.Attr) {
	value := attr.Value.Resolve()
	if attr.Key == "" && value.Kind() != slog.KindGroup {
		return
	}
	if value.Kind() != slog.KindGroup {
		dst[attr.Key] = value.Any()
		return
	}
	group := map[string]any{}
	for _, child := range value.Group() {
		addLogAttr(group, child)
	}
	if attr.Key == "" {
		for key, child := range group {
			dst[key] = child
		}
		return
	}
	dst[attr.Key] = group
}

func (h *pipeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &pipeHandler{pf: h.pf, level: h.level, attrs: merged, groups: h.groups}
}

func (h *pipeHandler) WithGroup(g string) slog.Handler {
	groups := append([]string(nil), h.groups...)
	groups = append(groups, g)
	return &pipeHandler{pf: h.pf, level: h.level, attrs: h.attrs, groups: groups}
}

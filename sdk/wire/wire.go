// Package wire defines the JSON-lines protocol spoken between the Reactor
// host (long-lived, owns DB + vault) and a workflow subprocess (short-lived,
// executes generated Go).
//
// Direction.
//   - Workflow stdout -> host stdin: requests + step results from generated code.
//   - Host stdout -> workflow stdin: responses + unsolicited push (signal delivery).
//
// Framing.
//
//	Each frame is one JSON object on one line, terminated by "\n". UTF-8.
//	No length prefix, no chunking. The encoder rejects payloads containing
//	raw newlines so the framing contract is unambiguous.
//
// IDs.
//
//	ID is a sender-local monotonic counter. Replies set Reply = request.ID
//	so the requesting side can fan replies into the right channel.
//
// Versioning.
//
//	The Hello frame carries protocol version; mismatches cause the workflow
//	subprocess to exit with a clear error before any business logic runs.
package wire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the wire protocol version. Bump on incompatible changes.
const Version = "wire.v1"

// Kind is the discriminator for a frame's body.
type Kind string

const (
	KindHello            Kind = "hello"             // bidirectional handshake
	KindStepStart        Kind = "step_start"        // workflow -> host
	KindStepEnd          Kind = "step_end"          // workflow -> host
	KindBlockReceipt     Kind = "block_receipt"     // workflow -> host; SDK-reported, value-free
	KindStepReply        Kind = "step_reply"        // host -> workflow (proceed | replay)
	KindAck              Kind = "ack"               // host -> workflow
	KindSleep            Kind = "sleep"             // workflow -> host
	KindAwaitSignal      Kind = "await_signal"      // workflow -> host
	KindSignalDeliver    Kind = "signal_deliver"    // host -> workflow
	KindSecretFetch      Kind = "secret_fetch"      // workflow -> host
	KindSecretReply      Kind = "secret_reply"      // host -> workflow
	KindConnectorRequest Kind = "connector_request" // workflow -> host; host attaches a credential
	KindConnectorReply   Kind = "connector_reply"   // host -> workflow; never contains a credential
	KindMailSendRequest  Kind = "mail_send_request" // workflow -> host; host owns provider endpoint and token
	KindMailSendReply    Kind = "mail_send_reply"   // host -> workflow; never contains a credential
	KindLog              Kind = "log"               // workflow -> host (one-way)
	KindCancel           Kind = "cancel"            // host -> workflow (graceful exit)
	KindError            Kind = "error"             // either direction (out-of-band)
)

// Frame is the on-wire envelope. Body is opaque per Kind so each side can
// share one Encode/Decode path without reflecting on every payload type.
type Frame struct {
	ID    int64           `json:"id"`
	Reply int64           `json:"reply,omitempty"`
	Kind  Kind            `json:"kind"`
	Body  json.RawMessage `json:"body,omitempty"`
}

// Hello is exchanged on connection. Either side may close the pipe if the
// version doesn't match.
type Hello struct {
	Version      string `json:"version"`
	WorkflowSlug string `json:"workflow_slug,omitempty"`
	RunID        string `json:"run_id,omitempty"`
	Mode         string `json:"mode,omitempty"` // "live" | "replay" | "dry_run"
	// SignalKey is the per-run signing key (hex) the workflow uses to compute
	// AwaitSignal capability tokens: token = HMAC(SignalKey, signalName). It is
	// delivered only over this private host->workflow frame, never exposed in
	// URLs/logs, so a party who knows only the runID cannot forge signal
	// tokens. Empty selects the legacy runID-only derivation.
	SignalKey string `json:"signal_key,omitempty"`
	// ObservedBlocks gates the additive block-receipt extension on a host that
	// can persist it. A new SDK fails closed on an older host instead of waiting
	// for an ACK that the older host will never send.
	ObservedBlocks bool `json:"observed_blocks,omitempty"`
	// ConnectorBroker advertises host-owned credential attachment for supported
	// connector requests. A new SDK fails closed on older hosts without it.
	ConnectorBroker bool `json:"connector_broker,omitempty"`
	// MailBroker advertises the host-owned Google/Microsoft send route. Older
	// hosts fail closed in the SDK before a workflow sends a mail frame.
	MailBroker bool `json:"mail_broker,omitempty"`
}

// BlockReceipt is SDK-reported metadata for one operation inside a claimed
// durable Step attempt. It deliberately contains no row, key, or error text.
type BlockReceipt struct {
	StepName    string `json:"step_name"`
	Seq         int64  `json:"seq"`
	Attempt     int    `json:"attempt"`
	CallOrdinal int    `json:"call_ordinal"`
	BlockID     string `json:"block_id"`
	Kind        string `json:"kind"`
	Mode        string `json:"mode"`
	LeftRows    int    `json:"left_rows"`
	RightRows   int    `json:"right_rows"`
	// For iterate and aggregate, OutputRows is the count of mapped items or
	// the one final accumulator. No item or accumulator value is sent.
	OutputRows int    `json:"output_rows"`
	MaxRows    int    `json:"max_rows"`
	InputRows  *int   `json:"input_rows,omitempty"`
	YesRows    *int   `json:"yes_rows,omitempty"`
	NoRows     *int   `json:"no_rows,omitempty"`
	Outcome    string `json:"outcome"`
}

// StepStart is what the workflow sends at every Step boundary. The host
// uses (run_id, step_name, idempotency_key) to look up cached output and
// reply with either StepReply{Replay: true, Output: ...} or {Replay: false}.
type StepStart struct {
	StepName       string `json:"step_name"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	InputHash      string `json:"input_hash,omitempty"`
	Attempt        int    `json:"attempt"`

	// DurableAttempts opts a rebuilt workflow into host-owned attempt
	// allocation. MaxAttempts is the total budget including the first call;
	// zero means the custom RetryPolicy did not expose a durable bound. These
	// fields are additive so old wire.v1 hosts ignore them and old workflow
	// binaries retain their legacy client-owned numbering.
	DurableAttempts bool `json:"durable_attempts,omitempty"`
	MaxAttempts     int  `json:"max_attempts,omitempty"`

	// Seq is the 1-based per-run CALL ORDINAL: the count of Step calls this
	// workflow has made, in program order. It is what makes a loop durable.
	// Without it the replay key was (run_id, step_name), so a Step reused
	// across iterations resolved every iteration to the FIRST one's journal
	// row: the side effect ran once, the rest were served stale output, and
	// the run still reported succeeded.
	//
	// Zero means the frame came from a workflow binary built against an SDK
	// that predates the ordinal. The host falls back to legacy (run_id,
	// step_name) semantics for those, so already-compiled customer workflows
	// keep running unchanged until they are rebuilt.
	Seq int64 `json:"seq,omitempty"`
}

// StepReply is the host's verdict on whether to replay or proceed.
type StepReply struct {
	Replay bool            `json:"replay"`
	Output json.RawMessage `json:"output,omitempty"` // present when Replay=true
	// RetryWaitMs means the previous retryable attempt's provider window has
	// not expired. The host has not allocated the next attempt; wait and send
	// the same StepStart again. Only new workflow binaries use this field.
	RetryWaitMs int64 `json:"retry_wait_ms,omitempty"`

	// Attempt is the host-assigned durable attempt number. Zero means the host
	// predates durable attempt allocation and the SDK falls back to its local
	// number. BudgetAttempt is relative to the current automatic/manual-redrive
	// window, while Attempt remains globally monotonic for the journal primary
	// key. RetryExhausted tells the SDK not to invoke the closure.
	Attempt        int  `json:"attempt,omitempty"`
	BudgetAttempt  int  `json:"budget_attempt,omitempty"`
	RetryExhausted bool `json:"retry_exhausted,omitempty"`
}

// StepEnd carries the result of a step the workflow actually executed.
// Output is the JSON-marshaled return value; ErrorText is empty on success.
// Retryable hints to the host whether to schedule a retry attempt.
type StepEnd struct {
	StepName string `json:"step_name"`
	Attempt  int    `json:"attempt"`
	// DurableAttempts lets a new host persist Retryable outcomes as an
	// explicit continuation checkpoint without changing legacy step rows.
	DurableAttempts bool `json:"durable_attempts,omitempty"`
	// Seq must match the StepStart that opened this step, so the host updates
	// the right journal row. Keyed on name alone, a loop's third iteration
	// overwrote the first iteration's row. Zero = pre-ordinal SDK.
	Seq       int64           `json:"seq,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
	ErrorText string          `json:"error_text,omitempty"`
	Retryable bool            `json:"retryable,omitempty"`
	// RetryAfterMs persists a provider's bounded minimum wait before the next
	// durable attempt. The host validates it and computes the deadline using
	// its own clock, so process restarts cannot lose the provider window.
	RetryAfterMs int64 `json:"retry_after_ms,omitempty"`
}

// Sleep yields the workflow until the wake time. For short sleeps the host
// keeps the subprocess alive and replies after the wait. For long sleeps
// the host writes a schedules row, kills the subprocess, and the scheduler
// re-spawns at wake_at; the new subprocess replays up to this Sleep call
// and observes "already elapsed".
type Sleep struct {
	StepName  string `json:"step_name"`
	UntilUnix int64  `json:"until_unix"` // seconds since epoch
	// Seq is the per-run call ordinal, from the same counter as StepStart.Seq
	// so it reflects program order across every durable operation. Without it a
	// Sleep inside a loop matched the first iteration's schedule row, whose
	// wake_at was already past, and every later iteration acked instantly.
	// Zero = pre-ordinal SDK, legacy (run_id, step_name, kind) lookup.
	Seq int64 `json:"seq,omitempty"`
}

// AwaitSignal blocks until a signal arrives or the timeout elapses.
type AwaitSignal struct {
	StepName   string `json:"step_name"`
	SignalName string `json:"signal_name"`
	TimeoutMs  int64  `json:"timeout_ms"` // 0 = no timeout
	// Seq is the per-run call ordinal, from the same counter as StepStart.Seq.
	// Two awaits sharing a signal name previously collapsed onto ONE schedule
	// row, so the second returned the first's already-delivered payload without
	// suspending and an approve-then-confirm gate auto-confirmed itself.
	// Zero = pre-ordinal SDK, legacy (run_id, step_name, kind) lookup.
	Seq int64 `json:"seq,omitempty"`
}

// SignalDeliver is the host's delivery of a signal payload to a blocked
// AwaitSignal. Empty Payload + Expired=true means the timeout fired.
// Token is the deterministic capability the external HTTP caller posted
// to; included so the workflow can confirm the right schedule was hit on
// resume.
type SignalDeliver struct {
	SignalName string          `json:"signal_name"`
	Token      string          `json:"token,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Expired    bool            `json:"expired,omitempty"`
}

// SecretFetch is the workflow's request for a credential value. The host
// resolves through the vault under vault_reader role and replies with a
// SecretReply. The plaintext is on the wire only between host and child
// process, never logged.
type SecretFetch struct {
	ID string `json:"id"`
}

// SecretReply carries the plaintext + fingerprint or an error.
type SecretReply struct {
	Value       []byte `json:"value,omitempty"` // base64-encoded by encoding/json
	Fingerprint string `json:"fingerprint,omitempty"`
	NotFound    bool   `json:"not_found,omitempty"`
}

// ConnectorRequest asks the host to perform a credential-bound HTTP call.
// The child supplies only a credential reference and provider-relative path;
// it cannot choose an origin or provide an Authorization header. The first
// supported operation is Salesforce GET under /services/data/.
type ConnectorRequest struct {
	CredentialID string `json:"credential_id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
}

// ConnectorReply returns a bounded provider response. Body contains only a
// successful GET response; errors expose stable codes and HTTP status, never
// provider error bodies, credentials, or request URLs.
type ConnectorReply struct {
	Status       int    `json:"status,omitempty"`
	Body         []byte `json:"body,omitempty"`
	RetryAfterMs int64  `json:"retry_after_ms,omitempty"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// MailSendRequest carries only a connection reference and a structured
// message. The host chooses the provider, HTTPS origin, path, and token.
type MailSendRequest struct {
	CredentialID   string      `json:"credential_id"`
	Message        MailMessage `json:"message"`
	StepName       string      `json:"step_name"`
	StepSeq        int64       `json:"step_seq"`
	StepAttempt    int         `json:"step_attempt"`
	IdempotencyKey string      `json:"idempotency_key"`
}

type MailMessage struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Cc      []string `json:"cc,omitempty"`
	Subject string   `json:"subject"`
	Text    string   `json:"text,omitempty"`
	HTML    string   `json:"html,omitempty"`
}

// MailSendReply exposes a provider message ID when available (Gmail) and a
// stable error code. Provider response bodies and tokens never cross the pipe.
type MailSendReply struct {
	MessageID string `json:"message_id,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Status    int    `json:"status,omitempty"`
}

// Log is one-way. The host forwards to its slog handler with run_id +
// workflow_slug attached so dashboard streaming gets a correctly-tagged line.
type Log struct {
	Level string         `json:"level"` // debug | info | warn | error
	Msg   string         `json:"msg"`
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Cancel asks the workflow to exit cleanly. Host uses this on graceful
// shutdown or when a run is cancelled via the dashboard.
type Cancel struct {
	Reason string `json:"reason"`
}

// Error is sent out-of-band when one side hits an unrecoverable wire
// problem (bad JSON, unknown kind). The receiving side typically closes
// the pipe and lets the supervisor mark the run failed.
type Error struct {
	Message string `json:"message"`
}

// ErrFrameTooLarge is returned by Decode when a single frame exceeds
// the line-buffer cap. The host enforces this to bound memory under
// hostile or buggy workflow output.
var ErrFrameTooLarge = errors.New("wire: frame exceeds maximum line length")

// ErrMalformedFrame is intentionally value-free. Workflow stdout can contain
// credentials or customer data, so decode errors must never echo its bytes
// into host logs or persisted run failures.
var ErrMalformedFrame = errors.New("wire: malformed frame")

// ErrMalformedBody is value-free for the same reason as ErrMalformedFrame:
// a child can place credential-like text in a JSON field name or value.
var ErrMalformedBody = errors.New("wire: malformed frame body")

// MaxFrameBytes caps a single frame at 1 MiB. Step outputs larger than
// this should land in object storage with a reference; this is checked
// at validation time.
const MaxFrameBytes = 1 << 20

// MaxSignalPayloadBytes is the largest JSON payload accepted by the public
// signal ingress. SignalDeliver wraps a payload in a JSON frame, so the
// payload must leave headroom for the frame envelope (signal name, token,
// reply ids, and future additive fields). Keeping this budget in the wire
// package lets HTTP, MCP, and the supervisor share the same transport bound.
const MaxSignalPayloadBytes = MaxFrameBytes - (64 << 10)

// Encoder writes frames to an io.Writer. Safe for one writer per Encoder.
type Encoder struct {
	w   *bufio.Writer
	buf bytes.Buffer
}

// NewEncoder wraps w. Callers must call Flush after each frame batch
// they want pushed to the kernel; Encode flushes per-frame so Flush is
// a no-op for normal use but matters for short-circuit shutdown paths.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: bufio.NewWriterSize(w, 1<<14)}
}

// Encode serializes f and writes a single line. Returns ErrFrameTooLarge
// if the resulting line would exceed MaxFrameBytes.
func (e *Encoder) Encode(f Frame) error {
	e.buf.Reset()
	if err := json.NewEncoder(&e.buf).Encode(f); err != nil {
		return fmt.Errorf("wire: encode: %w", err)
	}
	if e.buf.Len() > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	if _, err := e.w.Write(e.buf.Bytes()); err != nil {
		return fmt.Errorf("wire: write: %w", err)
	}
	return e.w.Flush()
}

// Decoder reads frames line-by-line. Not safe for concurrent readers;
// run one Decoder per pipe and dispatch via channels if you need fan-out.
type Decoder struct {
	r *bufio.Reader
}

// NewDecoder wraps r. The internal buffer grows up to MaxFrameBytes; oversized
// lines return ErrFrameTooLarge on the next Decode call.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReaderSize(r, 1<<14)}
}

// Decode reads the next frame. Returns io.EOF when the pipe closes.
func (d *Decoder) Decode() (Frame, error) {
	// Skip blank lines iteratively. A workflow subprocess is untrusted and can
	// emit arbitrary stdout; recursively calling Decode for each blank line
	// lets it grow the host stack until a panic before a valid frame arrives.
	for {
		var line []byte
		for {
			seg, err := d.r.ReadSlice('\n')
			if err == bufio.ErrBufferFull {
				line = append(line, seg...)
				if len(line) > MaxFrameBytes {
					return Frame{}, ErrFrameTooLarge
				}
				continue
			}
			if err != nil {
				if errors.Is(err, io.EOF) && len(seg) > 0 {
					line = append(line, seg...)
					break
				}
				return Frame{}, err
			}
			line = append(line, seg...)
			break
		}
		if len(line) > MaxFrameBytes {
			return Frame{}, ErrFrameTooLarge
		}
		// Strip trailing newline + optional \r.
		for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			// Empty line: continue without recursion. Surface EOF if the next
			// read has no more data.
			continue
		}
		var f Frame
		if err := json.Unmarshal(line, &f); err != nil {
			return Frame{}, ErrMalformedFrame
		}
		return f, nil
	}
}

// Wrap is a convenience for marshalling a typed body into a Frame.
func Wrap(id, reply int64, kind Kind, body any) (Frame, error) {
	if body == nil {
		return Frame{ID: id, Reply: reply, Kind: kind}, nil
	}
	b, err := json.Marshal(body)
	if err != nil {
		return Frame{}, fmt.Errorf("wire: marshal body: %w", err)
	}
	return Frame{ID: id, Reply: reply, Kind: kind, Body: b}, nil
}

// Unwrap extracts the typed body. Pass a pointer to the expected type.
func Unwrap(f Frame, into any) error {
	if len(f.Body) == 0 {
		return nil
	}
	if err := json.Unmarshal(f.Body, into); err != nil {
		return ErrMalformedBody
	}
	return nil
}

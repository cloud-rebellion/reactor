// Package wire re-exports the canonical wire protocol from sdk/wire so
// internal callers (supervisor, dispatcher, MCP server, tests) can keep
// their existing import path while out-of-module workflow authors land
// on the stable sdk/wire surface.
//
// The package contains no original code, only Go 1.9+ type aliases and
// var-binding re-exports. New shape additions go in sdk/wire; this file
// updates only when the SDK surface changes shape.
package wire

import (
	"io"

	sdkwire "github.com/bright-interaction/reactor/sdk/wire"
)

// Version is the wire protocol version; re-exported from sdk/wire.
const Version = sdkwire.Version

// MaxFrameBytes caps a single frame; re-exported from sdk/wire.
const MaxFrameBytes = sdkwire.MaxFrameBytes

// MaxSignalPayloadBytes leaves envelope headroom so a SignalDeliver frame
// always fits MaxFrameBytes; re-exported from sdk/wire.
const MaxSignalPayloadBytes = sdkwire.MaxSignalPayloadBytes

// Kind discriminates frame bodies; re-exported from sdk/wire.
type Kind = sdkwire.Kind

const (
	KindHello            = sdkwire.KindHello
	KindStepStart        = sdkwire.KindStepStart
	KindStepEnd          = sdkwire.KindStepEnd
	KindBlockReceipt     = sdkwire.KindBlockReceipt
	KindStepReply        = sdkwire.KindStepReply
	KindAck              = sdkwire.KindAck
	KindSleep            = sdkwire.KindSleep
	KindAwaitSignal      = sdkwire.KindAwaitSignal
	KindSignalDeliver    = sdkwire.KindSignalDeliver
	KindSecretFetch      = sdkwire.KindSecretFetch
	KindSecretReply      = sdkwire.KindSecretReply
	KindConnectorRequest = sdkwire.KindConnectorRequest
	KindConnectorReply   = sdkwire.KindConnectorReply
	KindMailSendRequest  = sdkwire.KindMailSendRequest
	KindMailSendReply    = sdkwire.KindMailSendReply
	KindLog              = sdkwire.KindLog
	KindCancel           = sdkwire.KindCancel
	KindError            = sdkwire.KindError
)

// Frame + body types re-exported as type aliases so existing call
// sites compose without conversions.
type (
	Frame            = sdkwire.Frame
	Hello            = sdkwire.Hello
	StepStart        = sdkwire.StepStart
	StepReply        = sdkwire.StepReply
	StepEnd          = sdkwire.StepEnd
	BlockReceipt     = sdkwire.BlockReceipt
	Sleep            = sdkwire.Sleep
	AwaitSignal      = sdkwire.AwaitSignal
	SignalDeliver    = sdkwire.SignalDeliver
	SecretFetch      = sdkwire.SecretFetch
	SecretReply      = sdkwire.SecretReply
	ConnectorRequest = sdkwire.ConnectorRequest
	ConnectorReply   = sdkwire.ConnectorReply
	MailSendRequest  = sdkwire.MailSendRequest
	MailSendReply    = sdkwire.MailSendReply
	MailMessage      = sdkwire.MailMessage
	Log              = sdkwire.Log
	Cancel           = sdkwire.Cancel
	Error            = sdkwire.Error
	Encoder          = sdkwire.Encoder
	Decoder          = sdkwire.Decoder
)

// ErrFrameTooLarge is the sentinel for oversize frames.
var ErrFrameTooLarge = sdkwire.ErrFrameTooLarge

// ErrMalformedFrame is the value-free sentinel for malformed child output.
var ErrMalformedFrame = sdkwire.ErrMalformedFrame

// ErrMalformedBody is the value-free sentinel for malformed child body JSON.
var ErrMalformedBody = sdkwire.ErrMalformedBody

// NewEncoder + NewDecoder + Wrap + Unwrap pass through to sdk/wire.
func NewEncoder(w io.Writer) *Encoder { return sdkwire.NewEncoder(w) }
func NewDecoder(r io.Reader) *Decoder { return sdkwire.NewDecoder(r) }

// Wrap marshals a typed body into a Frame.
func Wrap(id, reply int64, kind Kind, body any) (Frame, error) {
	return sdkwire.Wrap(id, reply, kind, body)
}

// Unwrap extracts a typed body from a Frame into the given pointer.
func Unwrap(f Frame, into any) error { return sdkwire.Unwrap(f, into) }

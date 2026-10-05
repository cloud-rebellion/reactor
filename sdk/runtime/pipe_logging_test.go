package runtime

import (
	"bytes"
	"log/slog"
	"reflect"
	"testing"

	"github.com/bright-interaction/reactor/sdk/wire"
)

// No String or MarshalJSON implementation: LogValue alone must protect this
// synthetic secret before it crosses the child-to-host pipe.
type logOnlySecret struct{ Plaintext string }

func (logOnlySecret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

type logSecretGroup struct{ Secret logOnlySecret }

func (g logSecretGroup) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("credential", g.Secret), slog.String("service", "fixture"))
}

func TestPipeLoggerHonorsLogValuerBeforeWritingFrames(t *testing.T) {
	t.Parallel()
	secret := logOnlySecret{Plaintext: "synthetic-wire-secret-canary"}
	for _, tc := range []struct {
		name string
		log  func(*slog.Logger)
		want map[string]any
	}{
		{"record", func(l *slog.Logger) { l.Info("event", "credential", secret) }, map[string]any{"credential": "[REDACTED]"}},
		{"bound", func(l *slog.Logger) { l.With("credential", secret).Info("event") }, map[string]any{"credential": "[REDACTED]"}},
		{"nested group", func(l *slog.Logger) {
			l.Info("event", slog.Group("request", slog.Group("auth", slog.Any("credential", secret)), slog.Int("attempt", 2)))
		}, map[string]any{"request": map[string]any{"auth": map[string]any{"credential": "[REDACTED]"}, "attempt": float64(2)}}},
		{"valuer returning group", func(l *slog.Logger) { l.With("account", logSecretGroup{secret}).Info("event") },
			map[string]any{"account": map[string]any{"credential": "[REDACTED]", "service": "fixture"}}},
		{"inline group", func(l *slog.Logger) { l.Info("event", slog.Group("", slog.Any("credential", secret)), slog.Attr{}) },
			map[string]any{"credential": "[REDACTED]"}},
		{"handler group", func(l *slog.Logger) { l.WithGroup("request").Info("event", "credential", secret) },
			map[string]any{"request": map[string]any{"credential": "[REDACTED]"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			pf := &PipeFlow{enc: wire.NewEncoder(&output)}
			tc.log(pf.Logger())
			if bytes.Contains(output.Bytes(), []byte(secret.Plaintext)) {
				t.Fatal("plaintext crossed the workflow-to-host pipe")
			}
			frame, err := wire.NewDecoder(&output).Decode()
			if err != nil {
				t.Fatal(err)
			}
			var record wire.Log
			if err := wire.Unwrap(frame, &record); err != nil {
				t.Fatal(err)
			}
			if frame.Kind != wire.KindLog || record.Msg != "event" || !reflect.DeepEqual(record.Attrs, tc.want) {
				t.Fatalf("log frame lost resolved attributes: %#v", record)
			}
		})
	}
}

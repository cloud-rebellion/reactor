package runtime

import (
	"testing"
	"time"

	"github.com/bright-interaction/reactor/sdk"
)

func TestHashOptsIncludesExplicitInputFingerprint(t *testing.T) {
	base := reactor.StepOpts{IdempotencyKey: "send:customer-1", Timeout: time.Second}
	first := hashOpts(base)
	second := hashOpts(reactor.StepOpts{IdempotencyKey: base.IdempotencyKey, InputHash: "customer-input-v1", Timeout: base.Timeout})
	third := hashOpts(reactor.StepOpts{IdempotencyKey: base.IdempotencyKey, InputHash: "customer-input-v2", Timeout: base.Timeout})
	if first == second || second == third {
		t.Fatalf("input fingerprint did not affect replay identity: first=%q second=%q third=%q", first, second, third)
	}
	if len(second) != 16 || len(third) != 16 {
		t.Fatalf("hash lengths = %d/%d, want 16", len(second), len(third))
	}
}

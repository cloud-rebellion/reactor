package runtime

import (
	"errors"
	"testing"
	"time"

	reactor "github.com/bright-interaction/reactor/sdk"
	reactorhttp "github.com/bright-interaction/reactor/sdk/http"
)

// TestRetryDecision pins the retry contract for the COMPILED-BINARY path, which
// is the one every real workflow uses. It had no retry loop at all: PipeFlow.Step
// called the closure once and returned, so a configured ExpBackoff{Max: 5}
// produced exactly one attempt. Only the in-process test flow implemented
// retries, which is why the suite never noticed.
//
// The classification was inverted on top of that: the old check required an
// explicit Retryable() wrapper, so a plain errors.New was never retried AND was
// reported to the host as terminal, which dead-lettered it on first failure.
// The rule is now the in-process flow's: with a policy set, retry anything not
// explicitly marked Permanent.
func TestRetryDecision(t *testing.T) {
	t.Parallel()
	policy := reactor.ExpBackoff{Max: 3, Base: time.Millisecond, Cap: time.Millisecond}

	cases := []struct {
		name      string
		policy    reactor.RetryPolicy
		err       error
		attempt   int
		wantRetry bool
	}{
		{"success never retries", policy, nil, 1, false},
		{"no policy means single attempt", nil, errors.New("boom"), 1, false},
		{"plain error retries under a policy", policy, errors.New("boom"), 1, true},
		{"explicitly retryable retries", policy, reactor.Retryable(errors.New("boom")), 1, true},
		{"permanent never retries", policy, reactor.Permanent(errors.New("bad input")), 1, false},
		{"permanent wins over retryable", policy, reactor.Permanent(reactor.Retryable(errors.New("x"))), 1, false},
		{"exhausted policy stops", policy, errors.New("boom"), 3, false},
		{"wrapped permanent is still permanent", policy, errors.Join(errors.New("ctx"), reactor.Permanent(errors.New("p"))), 1, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, got := retryDecision(tc.policy, tc.err, tc.attempt)
			if got != tc.wantRetry {
				t.Fatalf("retryDecision = %v, want %v", got, tc.wantRetry)
			}
		})
	}
}

func TestRetryDecisionRespectsProviderWindow(t *testing.T) {
	policy := reactor.ExpBackoff{Max: 3, Base: time.Millisecond, Cap: time.Millisecond}
	short := errors.Join(errors.New("provider read"), &reactorhttp.Error{Status: 429, RetryAfter: 4 * time.Second})
	delay, retry := retryDecision(policy, short, 1)
	if !retry || delay != 4*time.Second {
		t.Fatalf("short provider window = (%s, %t), want 4s retry", delay, retry)
	}
	long := &reactorhttp.Error{Status: 429, RetryAfter: 30 * time.Second, RetryAfterLong: true}
	if delay, retry := retryDecision(policy, long, 1); retry || delay != 0 {
		t.Fatalf("long provider window = (%s, %t), want terminal automatic retry", delay, retry)
	}
	if delay, retry := retryDecision(policy, reactor.Permanent(short), 1); retry || delay != 0 {
		t.Fatalf("permanent provider error = (%s, %t), want no retry", delay, retry)
	}
}

// TestIsPermanentIsTheRetryPredicate guards the marker semantics the retry loop
// depends on. IsRetryable is a strict marker test and is deliberately NOT the
// complement of IsPermanent; conflating them is what produced the inversion.
func TestIsPermanentIsTheRetryPredicate(t *testing.T) {
	t.Parallel()
	plain := errors.New("boom")

	if reactor.IsPermanent(nil) {
		t.Fatal("nil is not permanent")
	}
	if reactor.IsPermanent(plain) {
		t.Fatal("a plain error must not be permanent, or configured retries never fire")
	}
	if !reactor.IsPermanent(reactor.Permanent(plain)) {
		t.Fatal("Permanent() must be detected")
	}
	// The asymmetry that matters: a plain error is NOT IsRetryable (strict
	// marker test) yet IS retried, because the loop asks IsPermanent instead.
	if reactor.IsRetryable(plain) {
		t.Fatal("IsRetryable is a strict marker test; a plain error should not satisfy it")
	}
	if _, retry := retryDecision(reactor.ExpBackoff{Max: 2, Base: time.Millisecond}, plain, 1); !retry {
		t.Fatal("a plain error must still be retried under a policy")
	}
}

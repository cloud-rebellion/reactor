package server

import (
	"testing"
	"time"
)

func TestSafeNextPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/runs", "/runs"},
		{"/", "/"},
		{"", "/"},
		{"  /credentials  ", "/credentials"},
		{"//evil.com", "/"},       // protocol-relative open redirect
		{"/\\evil.com", "/"},      // backslash-smuggled
		{"https://evil.com", "/"}, // absolute
		{"javascript:alert(1)", "/"},
	}
	for _, c := range cases {
		if got := safeNextPath(c.in); got != c.want {
			t.Errorf("safeNextPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoginThrottleLocksAfterMaxFailures(t *testing.T) {
	tr := newLoginThrottle()
	now := time.Unix(1_700_000_000, 0)
	tr.now = func() time.Time { return now }
	key := "1.2.3.4|alice"

	for i := 0; i < tr.maxFailures-1; i++ {
		tr.recordFailure(key)
		if tr.locked(key) {
			t.Fatalf("locked too early after %d failures", i+1)
		}
	}
	tr.recordFailure(key) // crosses the threshold
	if !tr.locked(key) {
		t.Fatal("should be locked after max failures")
	}

	// A different key is unaffected (no global lockout).
	if tr.locked("1.2.3.4|bob") {
		t.Fatal("unrelated account should not be locked")
	}

	// Cooldown elapses -> unlocked again.
	now = now.Add(16 * time.Minute)
	if tr.locked(key) {
		t.Fatal("should be unlocked after cooldown")
	}

	// A success resets the counter.
	tr.recordFailure(key)
	tr.reset(key)
	if tr.locked(key) {
		t.Fatal("reset should clear the counter")
	}
}

func TestLoginThrottleBoundsDistinctFailuresAndExpiresOldEntries(t *testing.T) {
	tr := newLoginThrottle()
	tr.maxEntries = 2
	now := time.Unix(1_700_000_000, 0)
	tr.now = func() time.Time { return now }
	tr.recordFailure("1.2.3.4|alice")
	tr.recordFailure("1.2.3.4|bob")
	if len(tr.failures) != 2 || !tr.locked("1.2.3.4|charlie") {
		t.Fatalf("full tracker accepted an untracked identity: entries=%d", len(tr.failures))
	}
	tr.recordFailure("1.2.3.4|charlie")
	if len(tr.failures) != 2 {
		t.Fatalf("tracker grew past its cap: entries=%d", len(tr.failures))
	}
	tr.reset("1.2.3.4|alice")
	if tr.locked("1.2.3.4|charlie") {
		t.Fatal("released capacity did not admit another identity")
	}
	tr.recordFailure("1.2.3.4|charlie")
	now = now.Add(tr.lockWindow + time.Minute)
	if tr.locked("1.2.3.4|dana") || len(tr.failures) != 0 {
		t.Fatalf("old partial failures were not evicted: entries=%d", len(tr.failures))
	}
}

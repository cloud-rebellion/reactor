package server

import (
	"crypto/sha256"
	"sync"
	"time"
)

const maxLoginThrottleEntries = 50_000

// loginThrottle is an in-memory failed-login limiter. It bounds online
// password brute-forcing: after maxFailures failed attempts for a given
// (ip, username) key the key is locked for lockWindow. Keyed by the pair
// rather than by username alone so one attacker can't lock every account
// out from a single source, and not by IP alone so a shared proxy IP
// doesn't let one brute-forcer wedge unrelated accounts.
//
// This is a per-daemon guard. Multi-replica deployments need a shared ingress
// limit too; a restart clears the counters and therefore loosens the limit.
type loginThrottle struct {
	mu          sync.Mutex
	failures    map[[sha256.Size]byte]*throttleEntry
	maxFailures int
	maxEntries  int
	lockWindow  time.Duration
	lastSweep   time.Time
	now         func() time.Time
}

type throttleEntry struct {
	count       int
	lockedUntil time.Time
	lastSeen    time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{
		failures:    map[[sha256.Size]byte]*throttleEntry{},
		maxFailures: 5,
		maxEntries:  maxLoginThrottleEntries,
		lockWindow:  15 * time.Minute,
		now:         time.Now,
	}
}

// locked reports whether the key is currently in cooldown.
func (t *loginThrottle) locked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.sweepLocked(now)
	digest := sha256.Sum256([]byte(key))
	e := t.failures[digest]
	if e == nil {
		// Exhausting the bounded table must not turn new identities into
		// unlimited password or MFA guesses. A later expiry sweep restores
		// admission without growing memory.
		return len(t.failures) >= t.maxEntries
	}
	if e.lockedUntil.IsZero() {
		return false
	}
	if !now.Before(e.lockedUntil) {
		// Cooldown elapsed; reset so the next attempt starts fresh.
		delete(t.failures, digest)
		return false
	}
	return true
}

// recordFailure bumps the failure count and arms the lock once the
// threshold is crossed.
func (t *loginThrottle) recordFailure(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.sweepLocked(now)
	digest := sha256.Sum256([]byte(key))
	e := t.failures[digest]
	if e == nil {
		if len(t.failures) >= t.maxEntries {
			return // unknown keys are locked while the bounded table is full
		}
		e = &throttleEntry{}
		t.failures[digest] = e
	}
	e.count++
	e.lastSeen = now
	if e.count >= t.maxFailures {
		e.lockedUntil = now.Add(t.lockWindow)
	}
}

// reset clears the counter for a key after a successful login.
func (t *loginThrottle) reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, sha256.Sum256([]byte(key)))
}

// sweepLocked discards old partial failures as well as expired lockouts. The
// per-IP HTTP limiter bounds the rate of fresh keys; this cap bounds memory
// even when many source IPs or account names are involved. Hashing the key
// also prevents a very long submitted username from being retained in memory.
func (t *loginThrottle) sweepLocked(now time.Time) {
	if !t.lastSweep.IsZero() && now.Sub(t.lastSweep) < time.Minute {
		return
	}
	t.lastSweep = now
	for key, entry := range t.failures {
		if !entry.lockedUntil.IsZero() {
			if !now.Before(entry.lockedUntil) {
				delete(t.failures, key)
			}
		} else if !now.Before(entry.lastSeen.Add(t.lockWindow)) {
			delete(t.failures, key)
		}
	}
}

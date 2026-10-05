// Package cancelreg is a tiny process-local registry mapping a run id to
// the cause-aware cancellation of its executing supervisor. The dispatcher and
// the scheduler both register the runs they execute; the dashboard cancel
// handler and the cross-process cancel watcher call Cancel(runID) to kill
// a live run's subprocess (exec.CommandContext fires SIGKILL when the
// context is cancelled).
package cancelreg

import (
	"context"
	"errors"
	"sync"
)

// ErrInfrastructureShutdown distinguishes a process/drain timeout from an
// operator cancelling a run. Distributed supervisors must leave shutdown-
// interrupted work recoverable for lease expiry/reaping; explicit Cancel uses
// context.Canceled and remains a terminal user decision.
var ErrInfrastructureShutdown = errors.New("cancelreg: infrastructure shutdown")

// Registry is safe for concurrent use.
type Registry struct {
	mu   sync.Mutex
	next Registration
	m    map[string]map[Registration]func(error)
}

// Registration identifies one executing generation of a run. More than one
// generation can briefly coexist after lease expiry/reaping, so lifecycle
// cleanup must remove only its own registration.
type Registration uint64

// New returns an empty Registry.
func New() *Registry {
	return &Registry{m: map[string]map[Registration]func(error){}}
}

// Register records the cancel func for a running run. A nil Registry is a
// no-op so callers don't have to nil-check.
func (r *Registry) Register(runID string, cancel context.CancelFunc) Registration {
	if r == nil || runID == "" || cancel == nil {
		return 0
	}
	return r.RegisterCause(runID, func(error) { cancel() })
}

// RegisterCause records a cause-aware cancel func. Dispatcher uses this form
// so explicit operator cancellation and infrastructure shutdown reach the
// supervisor as distinct context causes.
func (r *Registry) RegisterCause(runID string, cancel context.CancelCauseFunc) Registration {
	if r == nil || runID == "" || cancel == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	if r.next == 0 {
		r.next++
	}
	if r.m == nil {
		r.m = map[string]map[Registration]func(error){}
	}
	if r.m[runID] == nil {
		r.m[runID] = map[Registration]func(error){}
	}
	r.m[runID][r.next] = cancel
	return r.next
}

// DeregisterRegistration removes exactly one executing generation. A stale
// generation finishing after a replacement registered must not erase the
// replacement's cancellation route.
func (r *Registry) DeregisterRegistration(runID string, registration Registration) {
	if r == nil || registration == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	registrations := r.m[runID]
	delete(registrations, registration)
	if len(registrations) == 0 {
		delete(r.m, runID)
	}
}

// Deregister drops every entry for a run. Retained for callers that explicitly
// own the whole run; execution lifecycles should use DeregisterRegistration.
func (r *Registry) Deregister(runID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.m, runID)
	r.mu.Unlock()
}

// Cancel invokes every live generation's cancel func for the run. Returns
// true when at least one execution was cancelled, false when the run is not on this
// daemon (suspended, already finished, or executing elsewhere).
func (r *Registry) Cancel(runID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	registrations := r.m[runID]
	funcs := make([]func(error), 0, len(registrations))
	for _, cancel := range registrations {
		funcs = append(funcs, cancel)
	}
	r.mu.Unlock()
	for _, cancel := range funcs {
		cancel(context.Canceled)
	}
	return len(funcs) > 0
}

// CancelAll cancels every registered execution and returns how many it
// signalled. Used at shutdown when graceful drain times out: killing each
// workflow subprocess (exec.CommandContext SIGKILL) stops that process from
// writing to a DB that is about to close. Descendants of a hostile binary
// still require the cgroup/container or deployment process supervisor to
// enforce a complete process-tree boundary. The cancel funcs are snapshotted
// under the lock so callers' Deregister doesn't race.
func (r *Registry) CancelAll() int {
	return r.CancelAllWithCause(context.Canceled)
}

// CancelAllWithCause cancels every registered run with one explicit cause.
// Worker/daemon drain timeouts use ErrInfrastructureShutdown; Cancel and the
// dashboard continue to use context.Canceled for terminal operator intent.
func (r *Registry) CancelAllWithCause(cause error) int {
	if r == nil {
		return 0
	}
	if cause == nil {
		cause = context.Canceled
	}
	r.mu.Lock()
	var funcs []func(error)
	for _, registrations := range r.m {
		for _, cancel := range registrations {
			funcs = append(funcs, cancel)
		}
	}
	r.mu.Unlock()
	for _, c := range funcs {
		c(cause)
	}
	return len(funcs)
}

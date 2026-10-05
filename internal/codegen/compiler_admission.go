package codegen

import (
	"context"
	"errors"
)

// ErrCompilerBusy means all active compiler slots and bounded waiting places
// are occupied. Callers may retry after other authoring jobs complete.
var ErrCompilerBusy = errors.New("codegen: compiler busy; retry later")

// A workflow build can start several Go compiler subprocesses. Limit the
// number of independent builds per Reactor process, including MCP validation,
// MCP/dashboard registration, and generator validation. The waiting bound
// prevents an HTTP burst from retaining unlimited source trees and goroutines.
var workflowCompilerAdmission = newCompilerAdmission(2, 16)

type compilerAdmission struct {
	active  chan struct{}
	waiting chan struct{}
}

type compilerAdmissionContextKey struct{}

func newCompilerAdmission(active, waiting int) *compilerAdmission {
	return &compilerAdmission{
		active:  make(chan struct{}, active),
		waiting: make(chan struct{}, waiting),
	}
}

func (a *compilerAdmission) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case a.waiting <- struct{}{}:
	default:
		return nil, ErrCompilerBusy
	}
	defer func() { <-a.waiting }()
	select {
	case a.active <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-a.active
			return nil, err
		}
		return func() { <-a.active }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// acquireContext lets ValidateWorkflowSource hold one slot across module
// preparation and its nested GoBuildValidator call. A direct generator call to
// GoBuildValidator acquires its own slot instead.
func (a *compilerAdmission) acquireContext(ctx context.Context) (context.Context, func(), error) {
	if ctx.Value(compilerAdmissionContextKey{}) == a {
		return ctx, func() {}, nil
	}
	release, err := a.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	return context.WithValue(ctx, compilerAdmissionContextKey{}, a), release, nil
}

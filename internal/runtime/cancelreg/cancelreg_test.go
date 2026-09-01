package cancelreg

import (
	"context"
	"errors"
	"testing"
)

func TestRegistryCancel(t *testing.T) {
	r := New()
	cancelled := false
	r.Register("run_1", func() { cancelled = true })

	// Cancelling a registered run fires its func and reports true.
	if !r.Cancel("run_1") {
		t.Fatal("Cancel should report true for a registered run")
	}
	if !cancelled {
		t.Fatal("cancel func was not invoked")
	}

	// Unknown run -> false, no panic.
	if r.Cancel("run_missing") {
		t.Fatal("Cancel should report false for an unknown run")
	}

	// Deregister removes it.
	r.Register("run_2", func() {})
	r.Deregister("run_2")
	if r.Cancel("run_2") {
		t.Fatal("Cancel should report false after Deregister")
	}
}

func TestRegistryDistinguishesOperatorCancelFromShutdown(t *testing.T) {
	r := New()
	operatorCtx, operatorCancel := context.WithCancelCause(context.Background())
	r.RegisterCause("operator", operatorCancel)
	if !r.Cancel("operator") {
		t.Fatal("operator cancel did not find run")
	}
	if cause := context.Cause(operatorCtx); !errors.Is(cause, context.Canceled) {
		t.Fatalf("operator cause = %v, want context.Canceled", cause)
	}

	shutdownCtx, shutdownCancel := context.WithCancelCause(context.Background())
	r.RegisterCause("shutdown", shutdownCancel)
	if got := r.CancelAllWithCause(ErrInfrastructureShutdown); got != 2 {
		t.Fatalf("shutdown cancel count = %d, want 2 registered entries", got)
	}
	if cause := context.Cause(shutdownCtx); !errors.Is(cause, ErrInfrastructureShutdown) {
		t.Fatalf("shutdown cause = %v, want infrastructure sentinel", cause)
	}
}

func TestRegistryCancelAll(t *testing.T) {
	r := New()
	n := 0
	r.Register("a", func() { n++ })
	r.Register("b", func() { n++ })
	r.Register("c", func() { n++ })
	if got := r.CancelAll(); got != 3 {
		t.Fatalf("CancelAll returned %d, want 3", got)
	}
	if n != 3 {
		t.Fatalf("expected 3 cancel funcs invoked, got %d", n)
	}
	// A nil registry is safe.
	var nilReg *Registry
	if nilReg.CancelAll() != 0 {
		t.Fatal("nil registry CancelAll should be 0")
	}
}

func TestRegistrySameRunGenerationsCannotUnregisterEachOther(t *testing.T) {
	r := New()
	oldCtx, oldCancel := context.WithCancelCause(context.Background())
	newCtx, newCancel := context.WithCancelCause(context.Background())
	oldRegistration := r.RegisterCause("same-run", oldCancel)
	r.RegisterCause("same-run", newCancel)

	// Both live generations must receive operator cancellation. This kills a
	// stale child as well as the healthy replacement if they briefly overlap.
	if !r.Cancel("same-run") {
		t.Fatal("same-run cancel did not find live generations")
	}
	if !errors.Is(context.Cause(oldCtx), context.Canceled) || !errors.Is(context.Cause(newCtx), context.Canceled) {
		t.Fatalf("same-run cancel causes: old=%v new=%v", context.Cause(oldCtx), context.Cause(newCtx))
	}

	// Recreate the overlap and let the stale generation finish first. Its exact
	// deregistration must leave the replacement reachable.
	r = New()
	oldCtx, oldCancel = context.WithCancelCause(context.Background())
	newCtx, newCancel = context.WithCancelCause(context.Background())
	oldRegistration = r.RegisterCause("same-run", oldCancel)
	r.RegisterCause("same-run", newCancel)
	r.DeregisterRegistration("same-run", oldRegistration)
	if !r.Cancel("same-run") {
		t.Fatal("stale deregistration removed replacement registration")
	}
	if cause := context.Cause(oldCtx); cause != nil {
		t.Fatalf("deregistered stale generation was signalled: %v", cause)
	}
	if cause := context.Cause(newCtx); !errors.Is(cause, context.Canceled) {
		t.Fatalf("replacement generation was not signalled: %v", cause)
	}
}

func TestRegistryNilSafe(t *testing.T) {
	var r *Registry // nil
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Register("x", cancel) // must not panic
	r.Deregister("x")
	if r.Cancel("x") {
		t.Fatal("nil registry Cancel should be false")
	}
}

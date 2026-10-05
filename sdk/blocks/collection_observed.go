package blocks

import (
	"context"
	"errors"
	"fmt"
)

// CollectionObservation contains only collection sizes. The workflow child
// reports these numbers; they do not attest to arbitrary Go behavior.
type CollectionObservation struct {
	BlockID    string
	InputRows  int
	OutputRows int
}

type IterateObserver interface {
	ObserveIterate(context.Context, CollectionObservation) error
}

type AggregateObserver interface {
	ObserveAggregate(context.Context, CollectionObservation) error
}

type iterateObserverKey struct{}
type aggregateObserverKey struct{}

// WithIterateObserver binds an observer to one supervised Step attempt.
func WithIterateObserver(ctx context.Context, observer IterateObserver) context.Context {
	return context.WithValue(ctx, iterateObserverKey{}, observer)
}

// WithAggregateObserver binds an observer to one supervised Step attempt.
func WithAggregateObserver(ctx context.Context, observer AggregateObserver) context.Context {
	return context.WithValue(ctx, aggregateObserverKey{}, observer)
}

// IterateObserved maps a bounded collection in input order and returns only
// after the host acknowledges a value-free receipt. Use Iterate for a pure
// calculation without a per-block observation. The callback should remain
// pure: replay and retries still occur at the enclosing durable Step.
func IterateObserved[T, R any](ctx context.Context, blockID string, in []T, fn func(T) R) ([]R, error) {
	if ctx == nil {
		return nil, errors.New("blocks: observed iterate requires a context")
	}
	observer, ok := ctx.Value(iterateObserverKey{}).(IterateObserver)
	if !ok || observer == nil {
		return nil, errors.New("blocks: observed iterate requires a supervised Step")
	}
	if !validObservedBlockID(blockID) {
		return nil, errors.New("blocks: observed iterate requires a valid block id")
	}
	if fn == nil {
		return nil, errors.New("blocks: observed iterate requires a mapping function")
	}
	if len(in) > MaxJoinRows {
		return nil, fmt.Errorf("blocks: observed iterate exceeds %d input rows", MaxJoinRows)
	}
	out := make([]R, len(in))
	for i, v := range in {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out[i] = fn(v)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := observer.ObserveIterate(ctx, CollectionObservation{BlockID: blockID, InputRows: len(in), OutputRows: len(out)}); err != nil {
		return nil, err
	}
	return out, nil
}

// AggregateObserved folds a bounded collection into one accumulator and
// returns only after the host acknowledges its value-free count receipt.
// The one output represents the final accumulator, including empty input.
func AggregateObserved[T, R any](ctx context.Context, blockID string, in []T, init R, fn func(R, T) R) (R, error) {
	var zero R
	if ctx == nil {
		return zero, errors.New("blocks: observed aggregate requires a context")
	}
	observer, ok := ctx.Value(aggregateObserverKey{}).(AggregateObserver)
	if !ok || observer == nil {
		return zero, errors.New("blocks: observed aggregate requires a supervised Step")
	}
	if !validObservedBlockID(blockID) {
		return zero, errors.New("blocks: observed aggregate requires a valid block id")
	}
	if fn == nil {
		return zero, errors.New("blocks: observed aggregate requires a folding function")
	}
	if len(in) > MaxJoinRows {
		return zero, fmt.Errorf("blocks: observed aggregate exceeds %d input rows", MaxJoinRows)
	}
	out := init
	for _, v := range in {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		out = fn(out, v)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := observer.ObserveAggregate(ctx, CollectionObservation{BlockID: blockID, InputRows: len(in), OutputRows: 1}); err != nil {
		return zero, err
	}
	return out, nil
}

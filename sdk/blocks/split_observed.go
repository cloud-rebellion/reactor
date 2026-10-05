package blocks

import (
	"context"
	"errors"
	"fmt"
)

// SplitObservation reports only collection sizes. It never contains a row or
// predicate value, and it does not attest that arbitrary child code is honest.
type SplitObservation struct {
	BlockID   string
	InputRows int
	YesRows   int
	NoRows    int
}

type SplitObserver interface {
	ObserveSplit(context.Context, SplitObservation) error
}

type splitObserverKey struct{}

// WithSplitObserver binds one supervised Step attempt to observed splits.
func WithSplitObserver(ctx context.Context, observer SplitObserver) context.Context {
	return context.WithValue(ctx, splitObserverKey{}, observer)
}

// SplitObserved partitions at most MaxJoinRows input rows and returns only
// after the host has acknowledged a value-free receipt. Use Split for pure
// calculations that do not need an observed visual block. A nil predicate is
// rejected rather than reporting an all-no branch as an observed decision.
func SplitObserved[T any](ctx context.Context, blockID string, in []T, pred func(T) bool) (yes, no []T, err error) {
	if ctx == nil {
		return nil, nil, errors.New("blocks: observed split requires a context")
	}
	observer, ok := ctx.Value(splitObserverKey{}).(SplitObserver)
	if !ok || observer == nil {
		return nil, nil, errors.New("blocks: observed split requires a supervised Step")
	}
	if !validObservedBlockID(blockID) {
		return nil, nil, errors.New("blocks: observed split requires a valid block id")
	}
	if pred == nil {
		return nil, nil, errors.New("blocks: observed split requires a predicate")
	}
	if len(in) > MaxJoinRows {
		return nil, nil, fmt.Errorf("blocks: observed split exceeds %d input rows", MaxJoinRows)
	}
	yes, no = make([]T, 0, len(in)), make([]T, 0, len(in))
	for _, value := range in {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if pred(value) {
			yes = append(yes, value)
		} else {
			no = append(no, value)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := observer.ObserveSplit(ctx, SplitObservation{BlockID: blockID, InputRows: len(in), YesRows: len(yes), NoRows: len(no)}); err != nil {
		return nil, nil, err
	}
	return yes, no, nil
}

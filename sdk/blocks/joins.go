package blocks

import (
	"context"
	"errors"
	"fmt"
)

// MaxJoinRows bounds one in-memory merge. Larger joins should be partitioned
// into durable Steps or handled by a database instead of materializing an
// unbounded Cartesian product in a workflow child.
const MaxJoinRows = 100_000

// JoinMode states which unmatched rows a key join keeps. Every matching
// left/right pair is emitted, including duplicates on either side.
type JoinMode string

const (
	JoinInner JoinMode = "inner"
	JoinLeft  JoinMode = "left"
	JoinRight JoinMode = "right"
	JoinFull  JoinMode = "full"
)

// Joined keeps presence separate from values because a zero-valued input
// record can be a real row. The missing side has its type's zero value.
type Joined[L, R any] struct {
	Left     L
	Right    R
	HasLeft  bool
	HasRight bool
}

// JoinObservation contains only operation metadata. Customer rows and key
// values never enter an observation or the Reactor wire protocol.
type JoinObservation struct {
	BlockID    string
	Mode       string
	LeftRows   int
	RightRows  int
	OutputRows int
	MaxRows    int
	Outcome    string // succeeded | bounded_failure
}

// JoinObserver is installed by the supervised runtime for one claimed Step
// attempt. It is intentionally not an attestation against hostile Go code:
// the child process can speak the wire protocol itself.
type JoinObserver interface {
	ObserveJoin(context.Context, JoinObservation) error
}

type joinObserverKey struct{}

// WithJoinObserver is used by the runtime to bind an observer to a Step
// closure. Standalone helper calls do not acquire a durable receipt.
func WithJoinObserver(ctx context.Context, observer JoinObserver) context.Context {
	return context.WithValue(ctx, joinObserverKey{}, observer)
}

// JoinByKeyObserved performs the same bounded join as JoinByKey and asks the
// current Step's runtime to record its value-free outcome before returning.
// It fails closed when there is no supervised observer; use JoinByKey for
// standalone calculations that do not require an observed visual block.
func JoinByKeyObserved[L, R any, K comparable](ctx context.Context, blockID string, left []L, right []R, leftKey func(L) K, rightKey func(R) K, mode JoinMode, maxRows int) ([]Joined[L, R], error) {
	if ctx == nil {
		return nil, errors.New("blocks: observed join requires a context")
	}
	observer, ok := ctx.Value(joinObserverKey{}).(JoinObserver)
	if !ok || observer == nil {
		return nil, errors.New("blocks: observed join requires a supervised Step")
	}
	if !validObservedBlockID(blockID) {
		return nil, errors.New("blocks: observed join requires a valid block id")
	}
	modeName := ""
	switch mode {
	case JoinInner:
		modeName = "inner_join"
	case JoinLeft:
		modeName = "left_join"
	case JoinRight:
		modeName = "right_join"
	case JoinFull:
		modeName = "full_join"
	default:
		return nil, errors.New("blocks: invalid observed join mode")
	}
	if err := validJoinLimit(maxRows); err != nil {
		return nil, err
	}
	if leftKey == nil || rightKey == nil {
		return nil, errors.New("blocks: join requires both key functions")
	}
	if len(left) > MaxJoinRows || len(right) > MaxJoinRows {
		return nil, fmt.Errorf("blocks: join input exceeds %d rows per side", MaxJoinRows)
	}
	out, joinErr := JoinByKey(left, right, leftKey, rightKey, mode, maxRows)
	observation := JoinObservation{BlockID: blockID, Mode: modeName, LeftRows: len(left), RightRows: len(right), OutputRows: len(out), MaxRows: maxRows, Outcome: "succeeded"}
	if joinErr != nil {
		observation.Outcome = "bounded_failure"
	}
	if err := observer.ObserveJoin(ctx, observation); err != nil {
		return nil, err
	}
	return out, joinErr
}

func validObservedBlockID(id string) bool {
	if len(id) == 0 || len(id) > 128 || !((id[0] >= 'a' && id[0] <= 'z') || (id[0] >= 'A' && id[0] <= 'Z')) {
		return false
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// JoinByKey combines collections using explicit SQL-like inner/left/right/full
// semantics. Output order is stable: walk left rows in input order and emit
// each matching right row in its input order, then append unmatched right rows
// in input order for right/full joins. Unlike MergeByKey's legacy last-right-
// wins behavior, duplicates produce all matching pairs. maxRows is mandatory
// and the function returns no partial output if the bound would be exceeded.
func JoinByKey[L, R any, K comparable](left []L, right []R, leftKey func(L) K, rightKey func(R) K, mode JoinMode, maxRows int) ([]Joined[L, R], error) {
	if leftKey == nil || rightKey == nil {
		return nil, errors.New("blocks: join requires both key functions")
	}
	if mode != JoinInner && mode != JoinLeft && mode != JoinRight && mode != JoinFull {
		return nil, errors.New("blocks: invalid join mode")
	}
	if err := validJoinLimit(maxRows); err != nil {
		return nil, err
	}
	if len(left) > MaxJoinRows || len(right) > MaxJoinRows {
		return nil, fmt.Errorf("blocks: join input exceeds %d rows per side", MaxJoinRows)
	}
	index := make(map[K][]int, len(right))
	for i, row := range right {
		key := rightKey(row)
		index[key] = append(index[key], i)
	}
	matchedRight := make([]bool, len(right))
	out := make([]Joined[L, R], 0, min(len(left)+len(right), maxRows))
	appendBounded := func(row Joined[L, R]) error {
		if len(out) == maxRows {
			return fmt.Errorf("blocks: join exceeds maxRows %d", maxRows)
		}
		out = append(out, row)
		return nil
	}
	for _, l := range left {
		matches := index[leftKey(l)]
		if len(matches) == 0 {
			if mode == JoinLeft || mode == JoinFull {
				if err := appendBounded(Joined[L, R]{Left: l, HasLeft: true}); err != nil {
					return nil, err
				}
			}
			continue
		}
		for _, i := range matches {
			matchedRight[i] = true
			if err := appendBounded(Joined[L, R]{Left: l, Right: right[i], HasLeft: true, HasRight: true}); err != nil {
				return nil, err
			}
		}
	}
	if mode == JoinRight || mode == JoinFull {
		for i, r := range right {
			if !matchedRight[i] {
				if err := appendBounded(Joined[L, R]{Right: r, HasRight: true}); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

// CrossJoin emits every left/right combination in stable nested-loop order.
// The cardinality is checked before allocation, including integer-overflow
// cases, so a mistaken all-combinations merge cannot exhaust a worker.
func CrossJoin[L, R any](left []L, right []R, maxRows int) ([]Joined[L, R], error) {
	if err := validJoinLimit(maxRows); err != nil {
		return nil, err
	}
	if len(left) == 0 || len(right) == 0 {
		return []Joined[L, R]{}, nil
	}
	if len(left) > maxRows/len(right) {
		return nil, fmt.Errorf("blocks: cross join exceeds maxRows %d", maxRows)
	}
	out := make([]Joined[L, R], 0, len(left)*len(right))
	for _, l := range left {
		for _, r := range right {
			out = append(out, Joined[L, R]{Left: l, Right: r, HasLeft: true, HasRight: true})
		}
	}
	return out, nil
}

// ZipAll combines by position and keeps the trailing rows from the longer
// side. Use presence flags to distinguish an unmatched row from a real zero
// value. Zip remains available when deliberately truncating to the shorter
// side is desired.
func ZipAll[L, R any](left []L, right []R, maxRows int) ([]Joined[L, R], error) {
	if err := validJoinLimit(maxRows); err != nil {
		return nil, err
	}
	n := max(len(left), len(right))
	if n > maxRows {
		return nil, fmt.Errorf("blocks: positional merge exceeds maxRows %d", maxRows)
	}
	out := make([]Joined[L, R], n)
	for i := 0; i < n; i++ {
		if i < len(left) {
			out[i].Left, out[i].HasLeft = left[i], true
		}
		if i < len(right) {
			out[i].Right, out[i].HasRight = right[i], true
		}
	}
	return out, nil
}

func validJoinLimit(maxRows int) error {
	if maxRows < 1 || maxRows > MaxJoinRows {
		return fmt.Errorf("blocks: maxRows must be 1..%d", MaxJoinRows)
	}
	return nil
}

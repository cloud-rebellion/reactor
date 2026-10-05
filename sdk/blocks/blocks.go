// Package blocks is Reactor's "block arsenal": the composable data and
// control-flow primitives an AI-generated workflow uses to shape data between
// Steps. These are the typed, generic equivalents of n8n's Switch, Merge,
// Filter, Item Lists, and Set nodes, but they are pure Go functions the AI
// judges how to wire, not frozen UI nodes. Robustness over n8n: every block is
// compile-checked, deterministic, and non-mutating (inputs are never changed in
// place, so replay is safe and there are no spooky side effects). Merges keep
// unmatched rows instead of silently dropping them.
//
// The ordinary helpers are pure transforms and do not need their own Step.
// Observed variants send value-free receipts and require a supervised Step.
package blocks

import (
	"sort"
)

// ---------------------------------------------------------------------------
// Routing: Switch / SwitchValue / If / Coalesce
// ---------------------------------------------------------------------------

// Case is one branch of a Switch: a predicate and the label to return when it
// matches. Name labels like a Go constant or a kebab branch name
// ("is-enterprise", "needs-review") so downstream code reads clearly.
type Case[T any] struct {
	When  func(T) bool
	Label string
}

// Switch returns the Label of the first Case whose predicate matches v, or
// fallback if none do. Use it to pick a named branch from a value, then drive a
// normal Go switch/if on the returned label.
//
//	route := blocks.Switch(order, []blocks.Case[Order]{
//	    {When: func(o Order) bool { return o.Total >= 1000 }, Label: "high-value"},
//	    {When: func(o Order) bool { return o.Total >= 100 }, Label: "standard"},
//	}, "low-value")
func Switch[T any](v T, cases []Case[T], fallback string) string {
	for _, c := range cases {
		if c.When != nil && c.When(v) {
			return c.Label
		}
	}
	return fallback
}

// Route is one branch of a SwitchValue: a predicate and the value to return.
type Route[T, R any] struct {
	When  func(T) bool
	Value R
}

// SwitchValue returns the Value of the first matching Route, else fallback. Use
// it to map an input to a result value (a price tier, a queue name, a template)
// without a chain of ifs.
func SwitchValue[T, R any](v T, routes []Route[T, R], fallback R) R {
	for _, r := range routes {
		if r.When != nil && r.When(v) {
			return r.Value
		}
	}
	return fallback
}

// If is a typed ternary (Go has none). Both branches are evaluated, so do not
// put side effects in them.
func If[T any](cond bool, then, els T) T {
	if cond {
		return then
	}
	return els
}

// Coalesce returns the first non-zero value, or the zero value if all are zero.
// Handy for "use the override, else the default".
func Coalesce[T comparable](vals ...T) T {
	var zero T
	for _, v := range vals {
		if v != zero {
			return v
		}
	}
	return zero
}

// ---------------------------------------------------------------------------
// Collection transforms: Map / Filter / Reduce / Unique / GroupBy / KeyBy /
// SortBy / Limit / Chunk / Flatten
// ---------------------------------------------------------------------------

// Map applies fn to each element and returns a new slice (input unchanged).
func Map[T, R any](in []T, fn func(T) R) []R {
	out := make([]R, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

// Iterate applies fn in input order and returns one result per item. It is an
// explicit name for the n8n Loop Over Items shape; unlike a durable Step loop,
// this helper is pure and sequential, so the enclosing Step remains the
// replay/timeout boundary and no hidden concurrency is introduced.
func Iterate[T, R any](in []T, fn func(T) R) []R {
	return Map(in, fn)
}

// Filter returns the elements for which pred is true, in order.
func Filter[T any](in []T, pred func(T) bool) []T {
	out := make([]T, 0, len(in))
	for _, v := range in {
		if pred(v) {
			out = append(out, v)
		}
	}
	return out
}

// Reduce folds in into a single accumulator, left to right.
func Reduce[T, R any](in []T, init R, fn func(acc R, v T) R) R {
	acc := init
	for _, v := range in {
		acc = fn(acc, v)
	}
	return acc
}

// Aggregate folds all items into one value. It is the named aggregation form
// used in generated workflow plans; Reduce remains the lower-level spelling.
func Aggregate[T, R any](in []T, init R, fn func(acc R, v T) R) R {
	return Reduce(in, init, fn)
}

// UniqueBy keeps the first element for each distinct key, preserving order.
// This is n8n's "Remove Duplicates" done deterministically.
func UniqueBy[T any, K comparable](in []T, key func(T) K) []T {
	seen := make(map[K]struct{}, len(in))
	out := make([]T, 0, len(in))
	for _, v := range in {
		k := key(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Unique is UniqueBy on the element itself (for comparable types).
func Unique[T comparable](in []T) []T {
	return UniqueBy(in, func(v T) T { return v })
}

// GroupBy buckets elements by key, preserving order within each bucket.
func GroupBy[T any, K comparable](in []T, key func(T) K) map[K][]T {
	out := make(map[K][]T)
	for _, v := range in {
		k := key(v)
		out[k] = append(out[k], v)
	}
	return out
}

// KeyBy indexes elements by key; on a key collision the last element wins.
func KeyBy[T any, K comparable](in []T, key func(T) K) map[K]T {
	out := make(map[K]T, len(in))
	for _, v := range in {
		out[key(v)] = v
	}
	return out
}

// SortBy returns a sorted copy (stable). The input slice is not modified, which
// keeps a Step's output deterministic across replays.
func SortBy[T any](in []T, less func(a, b T) bool) []T {
	out := make([]T, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// Limit returns at most the first n elements (n <= 0 returns empty).
func Limit[T any](in []T, n int) []T {
	if n <= 0 {
		return []T{}
	}
	if n >= len(in) {
		out := make([]T, len(in))
		copy(out, in)
		return out
	}
	out := make([]T, n)
	copy(out, in[:n])
	return out
}

// Chunk splits in into batches of at most size (n8n's "Split In Batches").
// size <= 0 returns the whole slice as one chunk.
func Chunk[T any](in []T, size int) [][]T {
	if size <= 0 {
		return [][]T{append([]T(nil), in...)}
	}
	var out [][]T
	for i := 0; i < len(in); i += size {
		end := i + size
		if end > len(in) {
			end = len(in)
		}
		out = append(out, append([]T(nil), in[i:end]...))
	}
	return out
}

// Split partitions in while preserving order. Items for which pred returns
// true are returned in yes; all others are returned in no. Both slices are
// newly allocated, so callers can safely mutate their results.
func Split[T any](in []T, pred func(T) bool) (yes, no []T) {
	yes = make([]T, 0, len(in))
	no = make([]T, 0, len(in))
	for _, v := range in {
		if pred != nil && pred(v) {
			yes = append(yes, v)
		} else {
			no = append(no, v)
		}
	}
	return yes, no
}

// Flatten concatenates a slice of slices into one.
func Flatten[T any](in [][]T) []T {
	n := 0
	for _, s := range in {
		n += len(s)
	}
	out := make([]T, 0, n)
	for _, s := range in {
		out = append(out, s...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Merges: Append / Zip / MergeByKey / MergeMaps
// ---------------------------------------------------------------------------

// Append concatenates sets in order (n8n's "Append" merge mode).
func Append[T any](sets ...[]T) []T {
	return Flatten(sets)
}

// Merge combines two collections by appending the right collection to the
// left. Use MergeByKey or Zip when the plan needs join or positional semantics
// instead of concatenation.
func Merge[T any](left, right []T) []T {
	return Append(left, right)
}

// Zip combines two slices positionally, stopping at the shorter length (n8n's
// "Combine by position" / multiplex).
func Zip[A, B, R any](a []A, b []B, fn func(A, B) R) []R {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]R, n)
	for i := 0; i < n; i++ {
		out[i] = fn(a[i], b[i])
	}
	return out
}

// MergeByKey joins right into left by key (n8n's "Combine by matching key"),
// left-join semantics: every left element is kept; when a right element shares
// its key, combine(left, right) replaces it; otherwise the left element passes
// through unchanged. Unlike n8n's merge, unmatched rows are never dropped. On
// duplicate right keys the last right wins (see KeyBy).
func MergeByKey[T any, K comparable](left, right []T, key func(T) K, combine func(l, r T) T) []T {
	idx := KeyBy(right, key)
	out := make([]T, len(left))
	for i, l := range left {
		if r, ok := idx[key(l)]; ok {
			out[i] = combine(l, r)
		} else {
			out[i] = l
		}
	}
	return out
}

// MergeMaps shallow-merges maps left to right into a new map; later maps win on
// key collisions (n8n's "Merge objects"). Inputs are not modified.
func MergeMaps[K comparable, V any](maps ...map[K]V) map[K]V {
	out := map[K]V{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

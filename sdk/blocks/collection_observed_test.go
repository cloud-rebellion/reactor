package blocks

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type collectionRecorder struct {
	iterate   CollectionObservation
	aggregate CollectionObservation
	err       error
}

func (r *collectionRecorder) ObserveIterate(_ context.Context, value CollectionObservation) error {
	r.iterate = value
	return r.err
}

func (r *collectionRecorder) ObserveAggregate(_ context.Context, value CollectionObservation) error {
	r.aggregate = value
	return r.err
}

func TestObservedCollectionsRequireAckAndReportOnlyCounts(t *testing.T) {
	type row struct{ Secret string }
	in := []row{{Secret: "private-a"}, {Secret: "private-b"}}
	if _, err := IterateObserved(context.Background(), "each", in, func(v row) string { return v.Secret }); err == nil || !strings.Contains(err.Error(), "supervised Step") {
		t.Fatalf("standalone iterate = %v", err)
	}
	if _, err := AggregateObserved(context.Background(), "sum", in, "", func(s string, v row) string { return s + v.Secret }); err == nil || !strings.Contains(err.Error(), "supervised Step") {
		t.Fatalf("standalone aggregate = %v", err)
	}
	recorder := &collectionRecorder{}
	ctx := WithAggregateObserver(WithIterateObserver(context.Background(), recorder), recorder)
	mapped, err := IterateObserved(ctx, "each", in, func(v row) string { return v.Secret })
	if err != nil || !reflect.DeepEqual(mapped, []string{"private-a", "private-b"}) ||
		recorder.iterate != (CollectionObservation{BlockID: "each", InputRows: 2, OutputRows: 2}) {
		t.Fatalf("iterate = %+v, %+v, %v", mapped, recorder.iterate, err)
	}
	sum, err := AggregateObserved(ctx, "sum", in, "", func(s string, v row) string { return s + v.Secret })
	if err != nil || sum != "private-aprivate-b" ||
		recorder.aggregate != (CollectionObservation{BlockID: "sum", InputRows: 2, OutputRows: 1}) {
		t.Fatalf("aggregate = %q, %+v, %v", sum, recorder.aggregate, err)
	}
	if strings.Contains(recorder.iterate.BlockID, "private") || strings.Contains(recorder.aggregate.BlockID, "private") {
		t.Fatal("observation exposed customer value")
	}
	recorder.err = errors.New("host rejected")
	if got, err := IterateObserved(ctx, "each", in, func(v row) string { return v.Secret }); err == nil || got != nil {
		t.Fatalf("unacknowledged iterate returned data: %+v, %v", got, err)
	}
	if got, err := AggregateObserved(ctx, "sum", in, "seed", func(s string, v row) string { return s + v.Secret }); err == nil || got != "" {
		t.Fatalf("unacknowledged aggregate returned data: %q, %v", got, err)
	}
	recorder.err = nil
	if got, err := AggregateObserved(ctx, "empty", []row(nil), "seed", func(s string, v row) string { return s + v.Secret }); err != nil || got != "seed" || recorder.aggregate.InputRows != 0 || recorder.aggregate.OutputRows != 1 {
		t.Fatalf("empty aggregate = %q, %+v, %v", got, recorder.aggregate, err)
	}
}

func TestObservedCollectionsRejectInvalidInputsBeforeCallback(t *testing.T) {
	recorder := &collectionRecorder{}
	ctx := WithAggregateObserver(WithIterateObserver(context.Background(), recorder), recorder)
	called := false
	mapFn := func(n int) int { called = true; return n }
	foldFn := func(sum, n int) int { called = true; return sum + n }
	if _, err := IterateObserved(ctx, "bad:id", []int{1}, mapFn); err == nil {
		t.Fatal("invalid iterate ID accepted")
	}
	if _, err := AggregateObserved(ctx, "bad:id", []int{1}, 0, foldFn); err == nil {
		t.Fatal("invalid aggregate ID accepted")
	}
	if _, err := IterateObserved(ctx, "each", make([]int, MaxJoinRows+1), mapFn); err == nil {
		t.Fatal("oversized iterate accepted")
	}
	if _, err := AggregateObserved(ctx, "sum", make([]int, MaxJoinRows+1), 0, foldFn); err == nil {
		t.Fatal("oversized aggregate accepted")
	}
	if _, err := IterateObserved[int, int](ctx, "each", []int{1}, nil); err == nil {
		t.Fatal("nil iterate callback accepted")
	}
	if _, err := AggregateObserved[int, int](ctx, "sum", []int{1}, 0, nil); err == nil {
		t.Fatal("nil aggregate callback accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := IterateObserved(cancelled, "each", []int{1}, mapFn); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled iterate = %v", err)
	}
	if _, err := AggregateObserved(cancelled, "sum", []int{1}, 0, foldFn); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled aggregate = %v", err)
	}
	if called {
		t.Fatal("rejected operation executed callback")
	}
}

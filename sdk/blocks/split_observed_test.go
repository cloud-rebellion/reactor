package blocks

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type splitRecorder struct {
	seen SplitObservation
	err  error
}

func (r *splitRecorder) ObserveSplit(_ context.Context, value SplitObservation) error {
	r.seen = value
	return r.err
}

func TestSplitObservedRequiresAckAndOnlyReportsCounts(t *testing.T) {
	type row struct {
		Secret string
		Pass   bool
	}
	in := []row{{"private-yes", true}, {"private-no", false}}
	pred := func(r row) bool { return r.Pass }
	if _, _, err := SplitObserved(context.Background(), "route", in, pred); err == nil || !strings.Contains(err.Error(), "supervised Step") {
		t.Fatalf("standalone observed split = %v", err)
	}
	recorder := &splitRecorder{}
	ctx := WithSplitObserver(context.Background(), recorder)
	yes, no, err := SplitObserved(ctx, "route", in, pred)
	if err != nil || !reflect.DeepEqual(yes, in[:1]) || !reflect.DeepEqual(no, in[1:]) {
		t.Fatalf("partition = %+v, %+v, %v", yes, no, err)
	}
	if recorder.seen != (SplitObservation{BlockID: "route", InputRows: 2, YesRows: 1, NoRows: 1}) ||
		strings.Contains(recorder.seen.BlockID, "private") {
		t.Fatalf("unsafe or wrong observation: %+v", recorder.seen)
	}
	recorder.err = errors.New("host rejected")
	if yes, no, err := SplitObserved(ctx, "route", in, pred); err == nil || yes != nil || no != nil {
		t.Fatalf("host rejection returned data: %+v, %+v, %v", yes, no, err)
	}
	if _, _, err := SplitObserved(ctx, "route", make([]row, MaxJoinRows+1), pred); err == nil {
		t.Fatal("oversized observed split accepted")
	}
	if _, _, err := SplitObserved(ctx, "bad:id", in, pred); err == nil {
		t.Fatal("invalid block id accepted")
	}
}

func TestSplitObservedRejectsMissingPredicateAndCancelledBranch(t *testing.T) {
	recorder := &splitRecorder{}
	ctx := WithSplitObserver(context.Background(), recorder)
	for _, input := range [][]int{nil, {1, 2}} {
		yes, no, err := SplitObserved(ctx, "route", input, nil)
		if err == nil || !strings.Contains(err.Error(), "requires a predicate") || yes != nil || no != nil {
			t.Fatalf("nil predicate routed input %v: yes=%v no=%v err=%v", input, yes, no, err)
		}
		if recorder.seen != (SplitObservation{}) {
			t.Fatalf("nil predicate produced an observation: %+v", recorder.seen)
		}
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelCtx = WithSplitObserver(cancelCtx, recorder)
	yes, no, err := SplitObserved(cancelCtx, "route", []int{1, 2}, func(v int) bool {
		cancel()
		return v == 1
	})
	if !errors.Is(err, context.Canceled) || yes != nil || no != nil || recorder.seen != (SplitObservation{}) {
		t.Fatalf("cancelled split returned a branch or receipt: yes=%v no=%v seen=%+v err=%v", yes, no, recorder.seen, err)
	}
}

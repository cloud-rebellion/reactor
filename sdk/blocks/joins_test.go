package blocks

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type joinObserverFunc func(context.Context, JoinObservation) error

func (f joinObserverFunc) ObserveJoin(ctx context.Context, item JoinObservation) error {
	return f(ctx, item)
}

func TestJoinByKeyObservedReportsOnlyValueFreeCounts(t *testing.T) {
	var got []JoinObservation
	ctx := WithJoinObserver(context.Background(), joinObserverFunc(func(_ context.Context, item JoinObservation) error {
		got = append(got, item)
		return nil
	}))
	type row struct{ Key, Customer string }
	left := []row{{"a", "private-left"}, {"a", "another-left"}}
	right := []row{{"a", "private-right"}, {"a", "another-right"}}
	key := func(r row) string { return r.Key }
	out, err := JoinByKeyObserved(ctx, "join", left, right, key, key, JoinFull, 4)
	if err != nil || len(out) != 4 || len(got) != 1 || got[0].Mode != "full_join" || got[0].OutputRows != 4 || got[0].Outcome != "succeeded" {
		t.Fatalf("observed join = %d/%v/%+v", len(out), err, got)
	}
	encoded, err := json.Marshal(got[0])
	if err != nil || strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), `"a"`) {
		t.Fatalf("observation contains row or key data: %s, %v", encoded, err)
	}
	out, err = JoinByKeyObserved(ctx, "join", left, right, key, key, JoinInner, 3)
	if err == nil || out != nil || len(got) != 2 || got[1].Outcome != "bounded_failure" || got[1].OutputRows != 0 {
		t.Fatalf("bound observation = %#v/%v/%+v", out, err, got)
	}
	if out, err := JoinByKeyObserved(context.Background(), "join", left, right, key, key, JoinInner, 4); err == nil || out != nil {
		t.Fatalf("unsupervised observed join succeeded: %#v/%v", out, err)
	}
}

func TestJoinByKeyPreservesDuplicatesAndUnmatchedRows(t *testing.T) {
	type row struct {
		Key int
		Tag string
	}
	left := []row{{1, "l1"}, {2, "l2"}, {1, "l3"}, {0, "l0"}}
	right := []row{{1, "r1"}, {1, "r2"}, {3, "r3"}, {0, "r0"}}
	key := func(r row) int { return r.Key }
	tests := []struct {
		mode JoinMode
		want []string
	}{
		{JoinInner, []string{"l1:r1", "l1:r2", "l3:r1", "l3:r2", "l0:r0"}},
		{JoinLeft, []string{"l1:r1", "l1:r2", "l2:-", "l3:r1", "l3:r2", "l0:r0"}},
		{JoinRight, []string{"l1:r1", "l1:r2", "l3:r1", "l3:r2", "l0:r0", "-:r3"}},
		{JoinFull, []string{"l1:r1", "l1:r2", "l2:-", "l3:r1", "l3:r2", "l0:r0", "-:r3"}},
	}
	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			got, err := JoinByKey(left, right, key, key, tc.mode, 20)
			if err != nil {
				t.Fatal(err)
			}
			labels := make([]string, 0, len(got))
			for _, pair := range got {
				l, r := "-", "-"
				if pair.HasLeft {
					l = pair.Left.Tag
				}
				if pair.HasRight {
					r = pair.Right.Tag
				}
				labels = append(labels, l+":"+r)
			}
			if !reflect.DeepEqual(labels, tc.want) {
				t.Fatalf("join pairs = %v, want %v", labels, tc.want)
			}
		})
	}
	if left[0].Tag != "l1" || right[0].Tag != "r1" {
		t.Fatal("join mutated its input slices")
	}
}

func TestJoinBoundsReturnNoPartialOutput(t *testing.T) {
	key := func(n int) int { return n }
	for _, tc := range []struct {
		name string
		run  func() (any, error)
	}{
		{"duplicate key expansion", func() (any, error) { return JoinByKey([]int{1, 1}, []int{1, 1}, key, key, JoinInner, 3) }},
		{"all pairs", func() (any, error) { return CrossJoin([]int{1, 2}, []int{3, 4}, 3) }},
		{"position", func() (any, error) { return ZipAll([]int{1, 2}, []string{"a"}, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.run()
			if err == nil || !reflect.ValueOf(out).IsNil() {
				t.Fatalf("overflow = %#v, %v; want no partial output", out, err)
			}
		})
	}
	if out, err := JoinByKey([]int{1}, []int{1}, key, key, JoinInner, 0); err == nil || out != nil {
		t.Fatalf("unbounded join accepted: %#v, %v", out, err)
	}
	if out, err := JoinByKey([]int{1}, []int{1}, nil, key, JoinInner, 1); err == nil || out != nil {
		t.Fatalf("missing key function accepted: %#v, %v", out, err)
	}
	if out, err := JoinByKey([]int{1}, []int{1}, key, key, JoinMode("mystery"), 1); err == nil || out != nil {
		t.Fatalf("unknown mode accepted: %#v, %v", out, err)
	}
	if out, err := JoinByKey(make([]int, MaxJoinRows+1), []int{1}, key, key, JoinInner, 1); err == nil || out != nil {
		t.Fatalf("oversized join input accepted: %#v, %v", out, err)
	}
}

func TestCrossJoinAndZipAllKeepPresence(t *testing.T) {
	product, err := CrossJoin([]int{0, 1}, []string{"a", "b"}, 4)
	if err != nil || len(product) != 4 || product[0].Left != 0 || product[0].Right != "a" || product[3].Left != 1 || product[3].Right != "b" {
		t.Fatalf("cross join = %+v, %v", product, err)
	}
	positional, err := ZipAll([]int{0, 1}, []string{"a"}, 2)
	if err != nil || len(positional) != 2 || !positional[0].HasLeft || !positional[0].HasRight || !positional[1].HasLeft || positional[1].HasRight {
		t.Fatalf("positional merge presence = %+v, %v", positional, err)
	}
}

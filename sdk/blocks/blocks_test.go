package blocks

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSwitch(t *testing.T) {
	cases := []Case[int]{
		{When: func(n int) bool { return n >= 100 }, Label: "high"},
		{When: func(n int) bool { return n >= 10 }, Label: "mid"},
	}
	tests := []struct {
		in   int
		want string
	}{{200, "high"}, {50, "mid"}, {5, "low"}, {100, "high"}, {10, "mid"}}
	for _, tt := range tests {
		if got := Switch(tt.in, cases, "low"); got != tt.want {
			t.Errorf("Switch(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSwitchValue(t *testing.T) {
	routes := []Route[string, int]{
		{When: func(s string) bool { return s == "eur" }, Value: 2},
		{When: func(s string) bool { return s == "usd" }, Value: 1},
	}
	if got := SwitchValue("eur", routes, -1); got != 2 {
		t.Errorf("got %d", got)
	}
	if got := SwitchValue("gbp", routes, -1); got != -1 {
		t.Errorf("fallback got %d", got)
	}
}

func TestIfAndCoalesce(t *testing.T) {
	if If(true, "a", "b") != "a" || If(false, "a", "b") != "b" {
		t.Fatal("If wrong")
	}
	if Coalesce("", "", "x", "y") != "x" {
		t.Fatal("Coalesce should pick first non-zero")
	}
	if Coalesce(0, 0, 7) != 7 {
		t.Fatal("Coalesce int")
	}
	if Coalesce("", "") != "" {
		t.Fatal("Coalesce all-zero")
	}
}

func TestMapFilterReduce(t *testing.T) {
	in := []int{1, 2, 3, 4}
	if got := Map(in, func(n int) int { return n * 2 }); !reflect.DeepEqual(got, []int{2, 4, 6, 8}) {
		t.Errorf("Map got %v", got)
	}
	if got := Filter(in, func(n int) bool { return n%2 == 0 }); !reflect.DeepEqual(got, []int{2, 4}) {
		t.Errorf("Filter got %v", got)
	}
	if got := Reduce(in, 0, func(a, v int) int { return a + v }); got != 10 {
		t.Errorf("Reduce got %d", got)
	}
	if got := Iterate(in, func(v int) int { return v * 3 }); !reflect.DeepEqual(got, []int{3, 6, 9, 12}) {
		t.Errorf("Iterate got %v", got)
	}
	if got := Aggregate(in, 0, func(a, v int) int { return a + v }); got != 10 {
		t.Errorf("Aggregate got %d", got)
	}
	// Input not mutated.
	if !reflect.DeepEqual(in, []int{1, 2, 3, 4}) {
		t.Errorf("input mutated: %v", in)
	}
}

func TestUniqueGroupKey(t *testing.T) {
	type rec struct {
		ID   int
		Name string
	}
	recs := []rec{{1, "a"}, {2, "b"}, {1, "a2"}, {3, "c"}}
	uniq := UniqueBy(recs, func(r rec) int { return r.ID })
	if len(uniq) != 3 || uniq[0].Name != "a" {
		t.Errorf("UniqueBy keeps first: %v", uniq)
	}
	if got := Unique([]int{1, 1, 2, 3, 3, 3}); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("Unique got %v", got)
	}
	grp := GroupBy(recs, func(r rec) int { return r.ID })
	if len(grp[1]) != 2 || len(grp[2]) != 1 {
		t.Errorf("GroupBy got %v", grp)
	}
	idx := KeyBy(recs, func(r rec) int { return r.ID })
	if idx[1].Name != "a2" { // last wins
		t.Errorf("KeyBy last-wins got %q", idx[1].Name)
	}
}

func TestSortLimitChunkFlatten(t *testing.T) {
	in := []int{3, 1, 2}
	sorted := SortBy(in, func(a, b int) bool { return a < b })
	if !reflect.DeepEqual(sorted, []int{1, 2, 3}) {
		t.Errorf("SortBy got %v", sorted)
	}
	if !reflect.DeepEqual(in, []int{3, 1, 2}) {
		t.Errorf("SortBy mutated input: %v", in)
	}
	if got := Limit([]int{1, 2, 3, 4}, 2); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf("Limit got %v", got)
	}
	if got := Limit([]int{1}, 5); !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("Limit over-len got %v", got)
	}
	if got := Limit([]int{1, 2}, 0); len(got) != 0 {
		t.Errorf("Limit 0 got %v", got)
	}
	chunks := Chunk([]int{1, 2, 3, 4, 5}, 2)
	if !reflect.DeepEqual(chunks, [][]int{{1, 2}, {3, 4}, {5}}) {
		t.Errorf("Chunk got %v", chunks)
	}
	if got := Flatten([][]int{{1, 2}, {3}, {}}); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("Flatten got %v", got)
	}
}

func TestMerges(t *testing.T) {
	if got := Append([]int{1, 2}, []int{3}, []int{4, 5}); !reflect.DeepEqual(got, []int{1, 2, 3, 4, 5}) {
		t.Errorf("Append got %v", got)
	}
	if got := Merge([]int{1, 2}, []int{3}); !reflect.DeepEqual(got, []int{1, 2, 3}) {
		t.Errorf("Merge got %v", got)
	}
	zipped := Zip([]int{1, 2, 3}, []string{"a", "b"}, func(n int, s string) string { return fmt.Sprintf("%d%s", n, s) })
	if !reflect.DeepEqual(zipped, []string{"1a", "2b"}) { // stops at shorter
		t.Errorf("Zip got %v", zipped)
	}
}

func TestSplit(t *testing.T) {
	yes, no := Split([]int{1, 2, 3, 4}, func(v int) bool { return v%2 == 0 })
	if !reflect.DeepEqual(yes, []int{2, 4}) || !reflect.DeepEqual(no, []int{1, 3}) {
		t.Fatalf("Split got yes=%v no=%v", yes, no)
	}
}

func TestMergeByKey(t *testing.T) {
	type rec struct {
		ID    int
		Name  string
		Email string
	}
	left := []rec{{1, "Ada", ""}, {2, "Grace", ""}, {3, "Lin", ""}}
	right := []rec{{1, "", "ada@x.com"}, {3, "", "lin@x.com"}}
	got := MergeByKey(left, right, func(r rec) int { return r.ID }, func(l, r rec) rec {
		l.Email = r.Email
		return l
	})
	// All left rows kept; matched rows enriched; unmatched (id 2) passes through.
	if len(got) != 3 || got[0].Email != "ada@x.com" || got[1].Email != "" || got[2].Email != "lin@x.com" {
		t.Errorf("MergeByKey got %+v", got)
	}
	if got[1].Name != "Grace" {
		t.Errorf("unmatched row not preserved: %+v", got[1])
	}
}

func TestMergeMaps(t *testing.T) {
	a := map[string]int{"x": 1, "y": 2}
	b := map[string]int{"y": 20, "z": 3}
	got := MergeMaps(a, b)
	want := map[string]int{"x": 1, "y": 20, "z": 3} // later wins
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MergeMaps got %v", got)
	}
	// Inputs not mutated.
	if a["y"] != 2 {
		t.Errorf("MergeMaps mutated input a: %v", a)
	}
}

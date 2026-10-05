package runlogs

import (
	"sync"
	"testing"
	"time"
)

func TestAppendAndSnapshot(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.Append("run_a", "first")
	b.Append("run_a", "second")
	b.Append("run_b", "other")
	got := b.Snapshot("run_a")
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("snapshot mismatch: %v", got)
	}
	if otherGot := b.Snapshot("run_b"); len(otherGot) != 1 || otherGot[0] != "other" {
		t.Fatalf("run_b leak / loss: %v", otherGot)
	}
}

func TestRingDropsOldestWhenFull(t *testing.T) {
	t.Parallel()
	b := New(3, time.Minute)
	for i, line := range []string{"a", "b", "c", "d", "e"} {
		_ = i
		b.Append("run_x", line)
	}
	got := b.Snapshot("run_x")
	if len(got) != 3 || got[0] != "c" || got[2] != "e" {
		t.Fatalf("ring drop wrong: %v", got)
	}
}

func TestByteCapDropsOldestLines(t *testing.T) {
	t.Parallel()
	b := New(100, time.Minute)
	b.maxBytes = 10
	for _, line := range []string{"1234", "5678", "90", "ab"} {
		b.Append("run_bytes", line)
	}
	got := b.Snapshot("run_bytes")
	if len(got) != 3 || got[0] != "5678" || got[1] != "90" || got[2] != "ab" {
		t.Fatalf("byte cap should drop oldest lines, got %v", got)
	}
	var total int
	for _, line := range got {
		total += len(line)
	}
	if total > b.maxBytes {
		t.Fatalf("buffer uses %d bytes, cap is %d", total, b.maxBytes)
	}
}

func TestOversizedLineIsReplacedWithBoundedMarker(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.maxBytes = 10
	sub := b.Subscribe("run_huge")
	defer b.Unsubscribe("run_huge", sub)
	b.Append("run_huge", "this line is far too large")

	got := b.Snapshot("run_huge")
	if len(got) != 1 || len(got[0]) > b.maxBytes {
		t.Fatalf("oversized line escaped byte cap: %q", got)
	}
	select {
	case streamed := <-sub:
		if streamed != got[0] {
			t.Fatalf("subscriber got %q, snapshot has %q", streamed, got[0])
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive bounded line")
	}
}

func TestSubscribeReceivesNewLines(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.Append("run_y", "before-subscribe")
	sub := b.Subscribe("run_y")
	defer b.Unsubscribe("run_y", sub)

	go func() {
		time.Sleep(10 * time.Millisecond)
		b.Append("run_y", "after-subscribe")
	}()

	select {
	case got := <-sub:
		if got != "after-subscribe" {
			t.Fatalf("got %q, want after-subscribe", got)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber timed out")
	}
}

func TestCloseClosesAllSubscribers(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	sub := b.Subscribe("run_z")
	b.Close("run_z")
	select {
	case _, ok := <-sub:
		if ok {
			t.Fatal("channel should be closed after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("close didn't propagate to subscriber")
	}
}

func TestSubscribeAfterCloseClosesImmediately(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.Append("run_w", "line")
	b.Close("run_w")
	sub := b.Subscribe("run_w")
	select {
	case _, ok := <-sub:
		if ok {
			t.Fatal("late subscriber should see closed channel")
		}
	case <-time.After(time.Second):
		t.Fatal("late subscribe to closed run did not close immediately")
	}
}

func TestSubscribeWithSnapshotIncludesTailAndSubscribesAtomically(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.Append("run_atomic", "before")
	snapshot, sub := b.SubscribeWithSnapshot("run_atomic")
	defer b.Unsubscribe("run_atomic", sub)

	if len(snapshot) != 1 || snapshot[0] != "before" {
		t.Fatalf("snapshot = %v, want [before]", snapshot)
	}
	b.Append("run_atomic", "after")
	select {
	case got := <-sub:
		if got != "after" {
			t.Fatalf("subscriber got %q, want after", got)
		}
	case <-time.After(time.Second):
		t.Fatal("atomic subscriber did not receive line appended after snapshot")
	}
}

func TestSubscribeWithSnapshotClosedRunReturnsTailAndClosedChannel(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.Append("run_closed_atomic", "terminal")
	b.Close("run_closed_atomic")

	snapshot, sub := b.SubscribeWithSnapshot("run_closed_atomic")
	if len(snapshot) != 1 || snapshot[0] != "terminal" {
		t.Fatalf("snapshot = %v, want [terminal]", snapshot)
	}
	select {
	case _, ok := <-sub:
		if ok {
			t.Fatal("closed run subscriber yielded a live line")
		}
	case <-time.After(time.Second):
		t.Fatal("closed run subscriber was not closed")
	}
}

func TestBeginReopensClosedRunForRetry(t *testing.T) {
	t.Parallel()
	b := New(10, time.Minute)
	b.Append("run_retry", "first attempt")
	b.Close("run_retry")
	b.Begin("run_retry")
	b.Append("run_retry", "retry attempt")
	got := b.Snapshot("run_retry")
	if len(got) != 1 || got[0] != "retry attempt" {
		t.Fatalf("retry state = %v, want only the new attempt", got)
	}
	sub := b.Subscribe("run_retry")
	defer b.Unsubscribe("run_retry", sub)
	b.Append("run_retry", "retry tail")
	select {
	case line := <-sub:
		if line != "retry tail" {
			t.Fatalf("retry subscriber got %q", line)
		}
	case <-time.After(time.Second):
		t.Fatal("retry subscriber did not receive new line")
	}
}

func TestConcurrentAppendsAreSafe(t *testing.T) {
	t.Parallel()
	b := New(1000, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Append("run_concurrent", "line")
			}
		}()
	}
	wg.Wait()
	if got := len(b.Snapshot("run_concurrent")); got != 1000 {
		t.Fatalf("got %d lines, want 1000", got)
	}
}

// TestAppendRacingCloseDoesNotPanic guards a daemon-killing regression.
// Append used to snapshot the subscriber set, RELEASE the per-run lock, and
// only then send. Close closes those same channels under that lock, and a
// select/default does not make a send on a closed channel safe: it panics.
// The panic surfaced on the dispatcher's supervisor goroutine, where the HTTP
// recoverer cannot see it, so an operator with a run tail open (or merely
// closing the tab) as a run finished took down the daemon and every other
// in-flight run. The existing concurrency test only raced Append against
// Append, which never reproduced it.
func TestAppendRacingCloseDoesNotPanic(t *testing.T) {
	t.Parallel()
	for i := 0; i < 300; i++ {
		b := New(10000, time.Minute)
		const runID = "run_race"

		// Drain every subscriber so Append keeps taking the real send branch.
		// A full 64-slot buffer makes the select fall to default, which hides
		// the bug: the send has to actually execute to panic.
		stop := make(chan struct{})
		var drains sync.WaitGroup
		for s := 0; s < 8; s++ {
			ch := b.Subscribe(runID)
			drains.Add(1)
			go func() {
				defer drains.Done()
				for {
					select {
					case _, ok := <-ch:
						if !ok {
							return
						}
					case <-stop:
						return
					}
				}
			}()
		}

		var wg sync.WaitGroup
		for a := 0; a < 8; a++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 200; k++ {
					b.Append(runID, "line")
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Close(runID)
		}()
		wg.Wait()
		close(stop)
		drains.Wait()
	}
}

// TestAppendAfterCloseIsDropped pins the other half of the same fix: a line
// accepted after Close showed up in the live SSE snapshot and then vanished
// on reload (Close flushes to the persist hook exactly once), and after the
// grace-window delete it resurrected a runState nothing ever reclaims.
func TestAppendAfterCloseIsDropped(t *testing.T) {
	t.Parallel()
	var persisted []string
	b := New(10, time.Minute)
	b.OnClose = func(_ string, lines []string) { persisted = append(persisted, lines...) }

	b.Append("run_x", "one")
	b.Close("run_x")
	b.Append("run_x", "two-after-close")

	got := b.Snapshot("run_x")
	if len(got) != 1 || got[0] != "one" {
		t.Fatalf("snapshot should hold only the pre-close line, got %v", got)
	}
	if len(persisted) != 1 || persisted[0] != "one" {
		t.Fatalf("persisted tail should match the snapshot, got %v", persisted)
	}
}

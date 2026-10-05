// Package runlogs is the in-process per-run log buffer + pub/sub
// behind the dashboard's /runs/{id}/tail SSE endpoint. Each run gets a
// ring buffer (default 1000 lines and 8 MiB) and zero-or-more subscriber
// channels. Both limits matter: a workflow can emit a small number of very
// large log lines, so a line-only cap is not a memory bound.
//
// Lifecycle: dispatcher Append's at the start of each run + on every
// supervisor log line, then Close's when the run terminates. Close
// drops the run's buffer + all subscriber channels after a grace
// window so a late SSE subscriber can still see the tail.
package runlogs

import (
	"fmt"
	"sync"
	"time"
)

const defaultMaxBytes = 8 << 20

// Buffer holds per-run rings + subscribers.
type Buffer struct {
	mu        sync.Mutex
	runs      map[string]*runState
	cap       int
	maxBytes  int
	graceTime time.Duration

	// OnClose, when set, receives a snapshot of a run's lines the moment
	// it terminates, before the in-memory state is dropped. The daemon
	// wires this to journal.SaveRunLogs so logs survive past the grace
	// window (the dashboard + MCP read them back from the DB). Optional.
	OnClose func(runID string, lines []string)
}

type runState struct {
	mu          sync.Mutex
	lines       []string
	bytes       int
	subscribers map[chan string]struct{}
	closed      bool
}

// New returns a Buffer with the given per-run line cap (default 1000),
// an 8 MiB per-run byte cap, and post-close grace window (default 10 minutes)
// before the run's state is dropped.
func New(cap int, grace time.Duration) *Buffer {
	if cap <= 0 {
		cap = 1000
	}
	if grace <= 0 {
		grace = 10 * time.Minute
	}
	return &Buffer{
		runs:      map[string]*runState{},
		cap:       cap,
		maxBytes:  defaultMaxBytes,
		graceTime: grace,
	}
}

// Append records one log line for a run. Creates the run's state if
// missing. If the buffer is full, drops the oldest line (ring shape).
func (b *Buffer) Append(runID, line string) {
	if runID == "" {
		return
	}
	b.mu.Lock()
	rs, ok := b.runs[runID]
	if !ok {
		rs = &runState{subscribers: map[chan string]struct{}{}}
		b.runs[runID] = rs
	}
	b.mu.Unlock()

	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed {
		// The run already terminated and Close() flushed its tail to the
		// persist hook exactly once. Accepting more lines here would show
		// them in the live SSE snapshot and then lose them on reload, and
		// after the grace-window delete it would resurrect a runState that
		// nothing ever reclaims.
		return
	}
	line = boundedLine(line, b.maxBytes)
	lineBytes := len(line)
	// Keep both bounds true. The byte cap is intentionally enforced before
	// the line-count cap so a single hostile line cannot evict useful history
	// and still exceed the memory budget.
	for len(rs.lines) > 0 && (len(rs.lines) >= b.cap || rs.bytes+lineBytes > b.maxBytes) {
		rs.bytes -= len(rs.lines[0])
		// Clear the backing-array slot before advancing the slice so evicted
		// strings are eligible for collection instead of being retained by
		// the ring's spare capacity.
		rs.lines[0] = ""
		rs.lines = rs.lines[1:]
	}
	if lineBytes > b.maxBytes {
		// maxBytes may only be lowered in package tests or future configuration;
		// keep the invariant even if it is set below the omission marker size.
		line = line[:b.maxBytes]
		lineBytes = len(line)
	}
	rs.lines = append(rs.lines, line)
	rs.bytes += lineBytes
	// Fan out while STILL HOLDING rs.mu. Close() closes these channels under
	// the same lock, and a select/default does NOT make a send on a closed
	// channel safe: it panics. Dropping the lock first (as this used to) let
	// an in-flight Append race a terminating run and panic on the
	// dispatcher's supervisor goroutine, where FlareRecoverer cannot see it,
	// killing the daemon and every other in-flight run with it. Holding the
	// lock cannot deadlock or backpressure because every send below is
	// non-blocking and the channels are buffered.
	for s := range rs.subscribers {
		select {
		case s <- line:
		default:
		}
	}
}

// Begin starts a new execution for runID. Dead-letter retries intentionally
// reuse the original run id so the durable step journal can replay successful
// work. A closed in-memory log state must therefore be replaced before the
// retry starts; otherwise every retry line is silently discarded after the
// first terminal Close.
func (b *Buffer) Begin(runID string) {
	if runID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	rs := b.runs[runID]
	if rs == nil {
		b.runs[runID] = &runState{subscribers: map[chan string]struct{}{}}
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !rs.closed {
		return
	}
	// Close already closed and detached all old subscribers. Start with a
	// fresh tail so a retry's live view is about that attempt, while the DB
	// retains the earlier attempt's persisted lines.
	b.runs[runID] = &runState{subscribers: map[chan string]struct{}{}}
}

func boundedLine(line string, maxBytes int) string {
	if maxBytes <= 0 || len(line) <= maxBytes {
		return line
	}
	marker := fmt.Sprintf("[reactor: log line omitted (%d bytes exceeds per-run limit)]", len(line))
	if len(marker) <= maxBytes {
		return marker
	}
	return marker[:maxBytes]
}

// Snapshot returns every buffered line for a run. Safe to call
// concurrently with Append.
func (b *Buffer) Snapshot(runID string) []string {
	b.mu.Lock()
	rs := b.runs[runID]
	b.mu.Unlock()
	if rs == nil {
		return nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]string, len(rs.lines))
	copy(out, rs.lines)
	return out
}

// SubscribeWithSnapshot returns the buffered tail and a live subscriber from
// one per-run lock acquisition. Callers that replay the tail before switching
// to live streaming must use this method: a separate Snapshot followed by
// Subscribe has a gap where Append can publish a line to neither the replay
// nor the new subscriber.
//
// The returned channel is buffered and MUST be passed to Unsubscribe when the
// caller stops consuming it, just like Subscribe.
func (b *Buffer) SubscribeWithSnapshot(runID string) ([]string, chan string) {
	b.mu.Lock()
	rs, ok := b.runs[runID]
	if !ok {
		rs = &runState{subscribers: map[chan string]struct{}{}}
		b.runs[runID] = rs
	}
	b.mu.Unlock()

	ch := make(chan string, 64)
	rs.mu.Lock()
	snapshot := make([]string, len(rs.lines))
	copy(snapshot, rs.lines)
	if rs.closed {
		// The snapshot still gives a late subscriber the completed tail; the
		// closed channel tells the caller there can be no more live lines.
		close(ch)
	} else {
		rs.subscribers[ch] = struct{}{}
	}
	rs.mu.Unlock()
	return snapshot, ch
}

// Subscribe returns a buffered channel that receives every subsequent
// Append for runID. Caller MUST Unsubscribe to release the channel +
// avoid the Buffer holding it forever.
func (b *Buffer) Subscribe(runID string) chan string {
	_, ch := b.SubscribeWithSnapshot(runID)
	return ch
}

// Unsubscribe removes ch from the run's subscriber set + closes it.
// Safe to call when the run has already been Close()d.
func (b *Buffer) Unsubscribe(runID string, ch chan string) {
	b.mu.Lock()
	rs := b.runs[runID]
	b.mu.Unlock()
	if rs == nil {
		return
	}
	rs.mu.Lock()
	if _, ok := rs.subscribers[ch]; ok {
		delete(rs.subscribers, ch)
		// Drain + close so the SSE goroutine exits cleanly.
		go func() {
			defer func() { recover() }()
			close(ch)
		}()
	}
	rs.mu.Unlock()
}

// Close marks a run as terminated. Subscribers' channels are closed
// so the SSE handlers return naturally; the run's state is dropped
// after the grace window so late subscribers still see the tail.
func (b *Buffer) Close(runID string) {
	b.mu.Lock()
	rs := b.runs[runID]
	b.mu.Unlock()
	if rs == nil {
		return
	}
	rs.mu.Lock()
	if rs.closed {
		rs.mu.Unlock()
		return
	}
	rs.closed = true
	// Snapshot the lines under the lock so the persist hook gets the full
	// tail even as a final Append races the Close.
	persisted := make([]string, len(rs.lines))
	copy(persisted, rs.lines)
	for ch := range rs.subscribers {
		close(ch)
	}
	rs.subscribers = map[chan string]struct{}{}
	rs.mu.Unlock()

	// Persist outside the lock so a slow DB write can't stall callers.
	if b.OnClose != nil && len(persisted) > 0 {
		b.OnClose(runID, persisted)
	}

	// Drop the run state after grace.
	time.AfterFunc(b.graceTime, func() {
		b.mu.Lock()
		// A DLQ retry may have started a fresh state for the same run id
		// before this old attempt's grace timer fires. Never delete the new
		// state from an earlier attempt's timer.
		if current := b.runs[runID]; current == rs {
			delete(b.runs, runID)
		}
		b.mu.Unlock()
	})
}

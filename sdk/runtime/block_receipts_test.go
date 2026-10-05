package runtime

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	sdk "github.com/bright-interaction/reactor/sdk"
	"github.com/bright-interaction/reactor/sdk/blocks"
	"github.com/bright-interaction/reactor/sdk/wire"
)

func TestObservedJoinWireWaitsForHostAckAndOmitsValues(t *testing.T) {
	hostToChildReader, hostToChildWriter := io.Pipe()
	childToHostReader, childToHostWriter := io.Pipe()
	t.Cleanup(func() {
		_ = hostToChildReader.Close()
		_ = hostToChildWriter.Close()
		_ = childToHostReader.Close()
		_ = childToHostWriter.Close()
	})
	flow := New(hostToChildReader, childToHostWriter, nil)
	observer := &stepBlockObserver{flow: flow, stepName: "merge-step", seq: 3, attempt: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = blocks.WithJoinObserver(ctx, observer)
	type row struct{ Key, Private string }
	left := []row{{Key: "sensitive-key", Private: "private-left"}}
	right := []row{{Key: "sensitive-key", Private: "private-right"}}
	key := func(r row) string { return r.Key }
	if _, err := blocks.JoinByKeyObserved(ctx, "join", left, right, key, key, blocks.JoinInner, 10); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unsupported host accepted observed join: %v", err)
	}
	flow.observedBlocks.Store(true)
	seen := make(chan wire.Frame, 1)
	go func() {
		frame, err := wire.NewDecoder(childToHostReader).Decode()
		if err != nil {
			seen <- wire.Frame{Kind: wire.KindError}
			return
		}
		seen <- frame
		ack, _ := wire.Wrap(4, frame.ID, wire.KindAck, nil)
		_ = wire.NewEncoder(hostToChildWriter).Encode(ack)
	}()
	out, err := blocks.JoinByKeyObserved(ctx, "join", left, right, key, key, blocks.JoinInner, 10)
	if err != nil || len(out) != 1 {
		t.Fatalf("observed join = %+v, %v", out, err)
	}
	frame := <-seen
	if frame.Kind != wire.KindBlockReceipt || strings.Contains(string(frame.Body), "private-") || strings.Contains(string(frame.Body), "sensitive-key") {
		t.Fatalf("unsafe observed wire frame: %+v", frame)
	}
	var body wire.BlockReceipt
	if err := wire.Unwrap(frame, &body); err != nil || body.StepName != "merge-step" || body.Seq != 3 || body.Attempt != 2 || body.CallOrdinal != 1 || body.LeftRows != 1 || body.RightRows != 1 || body.OutputRows != 1 {
		t.Fatalf("observed wire identity = %+v, %v", body, err)
	}
}

func TestObservedSplitSharesStepOrdinalAndOmitsPayload(t *testing.T) {
	hostToChildReader, hostToChildWriter := io.Pipe()
	childToHostReader, childToHostWriter := io.Pipe()
	t.Cleanup(func() {
		_ = hostToChildReader.Close()
		_ = hostToChildWriter.Close()
		_ = childToHostReader.Close()
		_ = childToHostWriter.Close()
	})
	flow := New(hostToChildReader, childToHostWriter, nil)
	observer := &stepBlockObserver{flow: flow, stepName: "route-step", seq: 3, attempt: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = blocks.WithSplitObserver(blocks.WithJoinObserver(ctx, observer), observer)
	type row struct {
		Private string
		Pass    bool
	}
	in := []row{{"private-yes", true}, {"private-no", false}}
	if _, _, err := blocks.SplitObserved(ctx, "route", in, func(r row) bool { return r.Pass }); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unsupported host accepted observed split: %v", err)
	}
	flow.observedBlocks.Store(true)
	seen := make(chan []wire.BlockReceipt, 1)
	go func() {
		decoder := wire.NewDecoder(childToHostReader)
		encoder := wire.NewEncoder(hostToChildWriter)
		var items []wire.BlockReceipt
		for i := 0; i < 2; i++ {
			frame, err := decoder.Decode()
			if err != nil || frame.Kind != wire.KindBlockReceipt || strings.Contains(string(frame.Body), "private-") {
				seen <- nil
				return
			}
			var body wire.BlockReceipt
			if wire.Unwrap(frame, &body) != nil {
				seen <- nil
				return
			}
			items = append(items, body)
			ack, _ := wire.Wrap(int64(i+10), frame.ID, wire.KindAck, nil)
			if encoder.Encode(ack) != nil {
				seen <- nil
				return
			}
		}
		seen <- items
	}()
	yes, no, err := blocks.SplitObserved(ctx, "route", in, func(r row) bool { return r.Pass })
	if err != nil || len(yes) != 1 || len(no) != 1 {
		t.Fatalf("observed split = %+v, %+v, %v", yes, no, err)
	}
	_, err = blocks.JoinByKeyObserved(ctx, "join", []int{1}, []int{1}, func(n int) int { return n }, func(n int) int { return n }, blocks.JoinInner, 10)
	if err != nil {
		t.Fatalf("observed join following split = %v", err)
	}
	items := <-seen
	if len(items) != 2 || items[0].Kind != "split" || items[0].CallOrdinal != 1 ||
		items[0].InputRows == nil || *items[0].InputRows != 2 || items[0].YesRows == nil || *items[0].YesRows != 1 ||
		items[0].NoRows == nil || *items[0].NoRows != 1 || items[0].StepName != "route-step" ||
		items[0].Seq != 3 || items[0].Attempt != 2 || items[1].Kind != "merge" || items[1].CallOrdinal != 2 {
		t.Fatalf("shared step receipt ordinals/counts = %+v", items)
	}
}

func TestObservedCollectionsShareStepOrdinalAndOmitValues(t *testing.T) {
	hostToChildReader, hostToChildWriter := io.Pipe()
	childToHostReader, childToHostWriter := io.Pipe()
	t.Cleanup(func() {
		_ = hostToChildReader.Close()
		_ = hostToChildWriter.Close()
		_ = childToHostReader.Close()
		_ = childToHostWriter.Close()
	})
	flow := New(hostToChildReader, childToHostWriter, nil)
	observer := &stepBlockObserver{flow: flow, stepName: "collection-step", seq: 4, attempt: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = blocks.WithAggregateObserver(blocks.WithIterateObserver(ctx, observer), observer)
	type row struct{ Secret string }
	in := []row{{"private-a"}, {"private-b"}}
	if _, err := blocks.IterateObserved(ctx, "each", in, func(v row) string { return v.Secret }); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unsupported host accepted observed iterate: %v", err)
	}
	flow.observedBlocks.Store(true)
	seen := make(chan []wire.BlockReceipt, 1)
	go func() {
		decoder := wire.NewDecoder(childToHostReader)
		encoder := wire.NewEncoder(hostToChildWriter)
		var items []wire.BlockReceipt
		for i := 0; i < 2; i++ {
			frame, err := decoder.Decode()
			if err != nil || frame.Kind != wire.KindBlockReceipt || strings.Contains(string(frame.Body), "private-") {
				seen <- nil
				return
			}
			var body wire.BlockReceipt
			if wire.Unwrap(frame, &body) != nil {
				seen <- nil
				return
			}
			items = append(items, body)
			ack, _ := wire.Wrap(int64(i+10), frame.ID, wire.KindAck, nil)
			if encoder.Encode(ack) != nil {
				seen <- nil
				return
			}
		}
		seen <- items
	}()
	mapped, err := blocks.IterateObserved(ctx, "each", in, func(v row) string { return v.Secret })
	if err != nil || len(mapped) != 2 {
		t.Fatalf("observed iterate = %+v, %v", mapped, err)
	}
	folded, err := blocks.AggregateObserved(ctx, "sum", in, "", func(s string, v row) string { return s + v.Secret })
	if err != nil || folded != "private-aprivate-b" {
		t.Fatalf("observed aggregate = %q, %v", folded, err)
	}
	items := <-seen
	if len(items) != 2 || items[0].Kind != "iterate" || items[0].CallOrdinal != 1 ||
		items[0].InputRows == nil || *items[0].InputRows != 2 || items[0].OutputRows != 2 ||
		items[1].Kind != "aggregate" || items[1].CallOrdinal != 2 ||
		items[1].InputRows == nil || *items[1].InputRows != 2 || items[1].OutputRows != 1 ||
		items[1].StepName != "collection-step" || items[1].Seq != 4 || items[1].Attempt != 2 {
		t.Fatalf("observed collection identity/counts = %+v", items)
	}
}

func TestStepInstallsObservedCollectionContexts(t *testing.T) {
	hostToChildReader, hostToChildWriter := io.Pipe()
	childToHostReader, childToHostWriter := io.Pipe()
	t.Cleanup(func() {
		_ = hostToChildReader.Close()
		_ = hostToChildWriter.Close()
		_ = childToHostReader.Close()
		_ = childToHostWriter.Close()
	})
	flow := New(hostToChildReader, childToHostWriter, nil)
	flow.observedBlocks.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type hostResult struct {
		receipts []wire.BlockReceipt
		err      error
	}
	seen := make(chan hostResult, 1)
	go func() {
		decoder := wire.NewDecoder(childToHostReader)
		encoder := wire.NewEncoder(hostToChildWriter)
		result := hostResult{}
		for i := 0; i < 4; i++ {
			frame, err := decoder.Decode()
			if err != nil {
				result.err = err
				break
			}
			var reply wire.Frame
			switch frame.Kind {
			case wire.KindStepStart:
				reply, err = wire.Wrap(int64(i+10), frame.ID, wire.KindStepReply, wire.StepReply{Attempt: 1})
			case wire.KindBlockReceipt:
				var body wire.BlockReceipt
				err = wire.Unwrap(frame, &body)
				if err == nil {
					result.receipts = append(result.receipts, body)
					reply, err = wire.Wrap(int64(i+10), frame.ID, wire.KindAck, nil)
				}
			case wire.KindStepEnd:
				reply, err = wire.Wrap(int64(i+10), frame.ID, wire.KindAck, nil)
			default:
				result.err = errors.New("unexpected child frame")
			}
			if result.err != nil || err != nil {
				if result.err == nil {
					result.err = err
				}
				break
			}
			if err = encoder.Encode(reply); err != nil {
				result.err = err
				break
			}
		}
		seen <- result
	}()
	out, err := flow.Step(ctx, "collection-step", sdk.StepOpts{}, func(stepCtx context.Context) (any, error) {
		mapped, err := blocks.IterateObserved(stepCtx, "each", []int{1, 2}, func(n int) int { return n * 2 })
		if err != nil {
			return nil, err
		}
		return blocks.AggregateObserved(stepCtx, "sum", mapped, 0, func(acc, n int) int { return acc + n })
	})
	if err != nil || out != 6 {
		t.Fatalf("observed Step result = %v, %v", out, err)
	}
	result := <-seen
	if result.err != nil || len(result.receipts) != 2 ||
		result.receipts[0].Kind != "iterate" || result.receipts[1].Kind != "aggregate" ||
		result.receipts[0].CallOrdinal != 1 || result.receipts[1].CallOrdinal != 2 ||
		result.receipts[0].StepName != "collection-step" || result.receipts[1].Seq != 1 {
		t.Fatalf("Step-bound receipts = %+v, %v", result.receipts, result.err)
	}
}

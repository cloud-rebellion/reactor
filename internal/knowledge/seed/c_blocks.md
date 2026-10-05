---
id: c_blocks
topic: connectors
title: Shape data with the block arsenal (Switch, Merge, Filter, ...)
created_by: seed
sources: []
tags: [blocks, switch, merge, filter, transforms, data-shaping]
gold: true
citation_count: 0
---

# Shape data with the block arsenal

`sdk/blocks` is the typed, generic equivalent of n8n's Switch / Merge / Filter
/ Item List nodes. They are pure, non-mutating functions, so use them inside or
between Step closures to route, filter, dedupe, group, batch, and merge data.
They never do IO, so they do not need their own Step. Prefer them over
hand-rolled loops: the intent reads clearly and the behaviour is consistent.

## Routing (Switch vs If)

- One condition, two outcomes: a plain Go `if` or `blocks.If(cond, a, b)`.
- Many conditions to a named branch: `blocks.Switch`. Return a label, then
  `switch` on it. Name labels like branches: "high-value", "needs-review".

```go
route := blocks.Switch(order, []blocks.Case[Order]{
    {When: func(o Order) bool { return o.Total >= 1000 }, Label: "high-value"},
    {When: func(o Order) bool { return o.Refunded }, Label: "refunded"},
}, "standard")
switch route {
case "high-value": // ...
}
```

Cases are evaluated in order; the first match wins. Put the most specific cases
first. Use `blocks.SwitchValue` to map straight to a value (a price tier, a
queue name) instead of a label.

## Merging

Pick a mode from the relationship between the two sides. Do not let an
unmatched or duplicate row disappear by accident:

- **Append** -> `blocks.Merge(left, right)` or `blocks.Append(sets...)`. Output
  is all of the left side followed by all of the right side.
- **Key join with duplicate matches** ->
  `blocks.JoinByKey(left, right, leftKey, rightKey, blocks.JoinFull, maxRows)`.
  Choose `JoinInner`, `JoinLeft`, `JoinRight`, or `JoinFull` deliberately. The
  result carries `HasLeft` and `HasRight` flags so a genuine zero-valued record
  is distinguishable from an absent side. Every matching pair is included in
  stable input order. `maxRows` is required and stops explosive joins.
- **Legacy one-right-row enrichment** -> `blocks.MergeByKey(left, right, key,
  combine)`. Every left row stays, but the *last* right row for a duplicate key
  wins. Use this only when that duplicate policy is intended.
- **Position** -> `blocks.ZipAll(left, right, maxRows)` keeps the longer side's
  unmatched tail with presence flags. `blocks.Zip(a, b, fn)` deliberately stops
  at the shorter side. Never pair by position when the sides can be out of
  order.
- **All combinations** -> `blocks.CrossJoin(left, right, maxRows)` with an
  explicit bound. Avoid this for large data sets; partition the operation or
  perform it in a database.
- **Objects/maps** -> `blocks.MergeMaps(base, override)`. Later maps win on key
  collisions.

The ordinary merge helpers are pure operations inside a durable Step. A `visual_flow` merge
block should declare the matching `mode` (`full_join`, `position_keep_all`,
`append`, and so on), a non-sensitive `key` for a key join, and the same literal
`max_rows` bound used by `JoinByKey`, `ZipAll`, or `CrossJoin`. The annotation
alone is not a runtime receipt.

When the customer needs a value-free observation for a key join, call
`blocks.JoinByKeyObserved(stepCtx, "join", left, right, leftKey, rightKey,
blocks.JoinFull, 1000)` directly inside the matching durable Step. Its literal
block ID, join mode, and bound must match a typed `visual_flow` merge block in
that same Step. Reactor rejects observed calls without the declaration. The
supervised SDK reports only row counts and a bounded outcome and waits for a
durable host acknowledgment. This remains an SDK-reported receipt, not proof
that arbitrary authored Go performed the join. For `NewInProcFlow` tests, bind
a recording `blocks.JoinObserver` with `blocks.WithJoinObserver` on the input
context; without an observer the helper fails closed. Use `JoinByKey` when an
operation receipt was not requested.

For a value-free item-loop observation, declare a matching `iterate` block
and call `blocks.IterateObserved(stepCtx, "each", rows, mapFn)` directly in its
Step closure. For a fold, declare a matching `aggregate` block and call
`blocks.AggregateObserved(stepCtx, "total", rows, initial, foldFn)` there.
Both helpers accept at most 100,000 input items and wait for a durable host
acknowledgment. Receipts contain only input/output counts (one aggregate
output accumulator), not item values. They cannot verify the mapping or fold.
Use ordinary `Iterate` or `Aggregate` when no block receipt is needed.

## Item-list transforms

`Map` (transform each), `Filter` (keep some), `Reduce` (fold to one),
`UniqueBy` (dedupe, keeps first occurrence, preserves order), `GroupBy`
(bucket by key), `KeyBy` (index by key, last wins), `SortBy` (returns a sorted
copy, input untouched), `Limit` (first N), `Chunk` (split into batches, e.g.
to respect an API's bulk-size limit), `Flatten`.

## Why this is robust

Every block returns a new value and never mutates its input, so a Step that
uses them stays deterministic and safe to replay. They are compile-checked
generics, so a type mistake fails the build, not production.

# Scaling: distributed mode + workers

Reactor runs in one of two modes, chosen with `--mode` (or `REACTOR_MODE`):

- **`local`** (default) -- single binary. Triggers execute workflows
  in-process as subprocesses, bounded by `REACTOR_MAX_CONCURRENT_RUNS`
  (default 32). SQLite or Postgres. Interrupted runs resume from durable Step,
  retry-attempt, and DLQ-repair checkpoints instead of resetting their bounded
  attempt budget. This is single-process recovery, not leased high
  availability: local mode remains useful for development and evaluation but
  is not the approved production topology for the Hash e-signature bridge.
- **`distributed`** -- horizontal scale. The daemon ENQUEUES runs; one or
  more `reactor worker` processes claim and execute them off a shared
  Postgres-backed queue. Add capacity by running more workers. **Requires
  Postgres** (SQLite can't back multiple worker processes).

There is no Redis, NATS, or Kubernetes requirement. The queue is the runs
table; the claim is a row lease. That is the whole point: durable
execution + horizontal scale on just Postgres.

## How it works

```
                 ┌───────────────────────────┐
   triggers ───► │ reactor serve --mode       │   (HTTP, enqueue, leader:
 (webhook/cron/  │   distributed              │    scheduler + cron)
  manual/chain)  └─────────────┬─────────────┘
                               │ INSERT runs (status=queued)
                               ▼
                       ┌───────────────┐
                       │  Postgres     │  runs (the queue) + leases
                       └───────┬───────┘
            claim (SKIP LOCKED)│  ▲ lease heartbeat / release
              ┌────────────────┼──┴────────────────┐
              ▼                ▼                    ▼
      ┌─────────────┐  ┌─────────────┐      ┌─────────────┐
      │ reactor     │  │ reactor     │ ...  │ reactor     │
      │ worker #1   │  │ worker #2   │      │ worker #N   │
      └─────────────┘  └─────────────┘      └─────────────┘
```

- A trigger creates a run with status `queued`.
- Each worker `SELECT ... FOR UPDATE SKIP LOCKED`s a batch of queued runs,
  flips them to `running`, and writes a **lease** (`run_id, worker_id,
  expires_at`). SKIP LOCKED guarantees no two workers grab the same run.
- While a run executes, the worker **heartbeats** its lease. If a worker
  dies, its lease expires and any worker's reaper requeues the run
  (`status` back to `queued`). Re-running is safe: the supervisor replays
  completed steps from the journal, so the run resumes rather than
  repeating side effects.
- Queue admission pins the exact content-addressed workflow artifact. All API
  and worker nodes therefore need the same durable artifact set. Execution
  nodes must receive it through a read-only shared mount or an atomic,
  checksum-verified distribution; they must not rewrite artifacts in place. A
  rolling v2 activation cannot make an existing v1 run execute v2; v1 resolves
  its historical digest. An invalid or unpinned persisted identity fails the
  run through the terminal artifact fence. When the identity is valid but a
  node cannot read or verify its local bytes, execution stays blocked and the
  exact run/schedule remains recoverable with bounded backoff and an
  operator-visible run-log marker. It never falls through to newer bytes.
- Sleep/signal **resumes** are re-enqueued too -- the scheduler flips a
  woken run back to `queued` and a worker picks it up, so long-running and
  suspended workloads also spread across the fleet.
- **Leader election:** in distributed mode the scheduler, cron driver, and
  rotation runner run on exactly one `serve` instance, elected by a
  Postgres advisory lock. Run multiple `serve` daemons for HA: followers
  serve HTTP + enqueue, and one takes over leadership if the leader dies.

The journal cache closes the ordinary process-crash gap only after a Step's
successful result is committed. There is necessarily a smaller external-commit
gap: a worker can die after Hash accepted a create-and-send command but before
Reactor records `StepEnd`. The replacement worker must execute that Step again.
Hash Steps are safe only because both attempts reuse the exact stable external
event-derived Reactor Step key and Hash `Idempotency-Key`; Hash returns the
original document rather than creating another. Never derive either key from a
retry number, timestamp, worker, or deployment version. The lifecycle bridge
uses the same rule with Hash `event_id` and BrightCRM's durable dedup record.

## Running it

```bash
# one (or more) API + leader daemon(s)
reactor serve --mode distributed --db postgres://user:pw@db/reactor --root /var/lib/reactor

# as many workers as you need, same DB + immutable artifact set
reactor worker --db postgres://user:pw@db/reactor --root /var/lib/reactor --concurrency 16
reactor worker --db postgres://user:pw@db/reactor --root /var/lib/reactor --concurrency 16
```

Each worker runs up to `--concurrency` runs at once (default = CPU count).
To add capacity, start more workers; to remove it, stop them (SIGINT
drains in-flight runs first).

### Config

| Flag / env | Default | What |
| --- | --- | --- |
| `--mode` / `REACTOR_MODE` | `local` | `local` or `distributed` |
| `--concurrency` / `REACTOR_WORKER_CONCURRENCY` | CPU count | max concurrent runs per worker |
| `--lease-ttl` | `60s` | lease validity; heartbeated while running, reaped if a worker dies |
| `--poll-interval` | `2s` | how often an idle worker polls for work |
| `--drain-timeout` / `REACTOR_DRAIN_TIMEOUT` | `30s` | shutdown grace before in-flight runs are killed |

### Retry/DLQ version cutovers

The release that introduces durable `dlq_pending` repair checkpoints and exact
DLQ step identity is not safe as a mixed old/new worker rollout. Before applying
that release or migration, quiesce admission, disable any autoscaler that could
start the old image, gracefully drain every old worker, and verify that no old
worker process remains. Apply the migrations, distribute the reviewed immutable
artifacts, upgrade `serve` and the worker image, then start only new-version
workers and run restart plus DLQ-redrive smoke tests before reopening admission.

## Autoscaling (optional)

Workers are stateless and identical, so "Reactor duplicating itself to
handle load" is just running more `reactor worker` processes. The daemon
can do that for you: pass `--autoscale` (or `REACTOR_AUTOSCALE=1`) to a
`serve --mode distributed` instance and the **leader** runs a controller
that spawns and stops workers to track queue depth.

```bash
reactor serve --mode distributed --autoscale --db postgres://... --root /var/lib/reactor
```

Every 15s the controller reads the queue depth and computes a target
worker count = `ceil(queued / queue_per_worker)`, clamped to `[min, max]`,
and moves **one worker per tick** toward it. The defaults are deliberately
safe, because a self-replicating system must never run away:

- **`REACTOR_AUTOSCALE_MAX`** (default `4`) is a HARD cap. The controller
  never spawns past it.
- Scale-up is paced by a cooldown, so even sustained load ramps one worker
  at a time rather than bursting.
- Scale-down only happens after the queue has stayed empty for a cooldown
  (no flapping).
- **`REACTOR_AUTOSCALE_MIN`** (default `0`) lets the pool scale to zero
  when idle (no workers, no cost) and back up on the next burst.

| Env | Default | What |
| --- | --- | --- |
| `--autoscale` / `REACTOR_AUTOSCALE` | off | enable the autoscaler (leader, distributed only) |
| `REACTOR_AUTOSCALE_MIN` | `0` | minimum workers (0 = scale to zero) |
| `REACTOR_AUTOSCALE_MAX` | `4` | HARD cap on workers |
| `REACTOR_AUTOSCALE_QUEUE_PER_WORKER` | `20` | queued runs per worker before adding one |

The dashboard home shows the live fleet (active workers + total
concurrency + queue depth) so you can watch it work.

### Where workers run (the spawner)

By default the autoscaler spawns workers as **child processes on the same
host** -- zero setup, bounded by that one box. To scale across a fleet,
point it at an orchestrator with `REACTOR_AUTOSCALE_SPAWNER`. Reactor does
not link the Docker or Kubernetes SDKs; it shells out to your own CLI, so
one mechanism covers every cluster manager and pins no client version.

| `REACTOR_AUTOSCALE_SPAWNER` | Spawns a worker by | Needs |
| --- | --- | --- |
| `process` (default) | re-execing this binary as `reactor worker` | nothing |
| `docker` | `docker run -d <image> worker ...` | `REACTOR_WORKER_IMAGE`, a reachable Docker daemon |
| `kubernetes` | `kubectl create` of a worker `Job` | `REACTOR_WORKER_IMAGE`, a working `kubectl` context |
| `command` | running your own shell commands | `REACTOR_AUTOSCALE_SPAWN_CMD` (+ `_STOP_CMD`) |

All four are driven by the same controller and the same `MIN`/`MAX`/cooldown
safety. The hard `MAX` cap matters most off-host: it bounds how many
containers or Pods the autoscaler can ever create.

**docker.** The worker container runs `worker --db <db> --root <root>`.
Workers need the compiled workflow binaries under `--root`. For a production
fleet, provide the reviewed artifact set through a read-only mount (or an
atomic, checksum-verified local distribution) and set the DB network with
`REACTOR_AUTOSCALE_DOCKER_ARGS`, for example:

```bash
REACTOR_AUTOSCALE_SPAWNER=docker \
REACTOR_WORKER_IMAGE=registry.example.com/reactor:latest \
REACTOR_AUTOSCALE_DOCKER_ARGS="-v /var/lib/reactor:/var/lib/reactor:ro --network host" \
reactor serve --mode distributed --autoscale --db postgres://... --root /var/lib/reactor
```

**kubernetes.** Each scale-up `kubectl create`s a `Job` (`generateName:
reactor-worker-`, `ttlSecondsAfterFinished` so finished Jobs are collected);
scale-down deletes it. Set `REACTOR_AUTOSCALE_K8S_NAMESPACE` (default
`default`). Keep the DB password out of the manifest by pointing at a
Secret: `REACTOR_AUTOSCALE_K8S_DB_SECRET=reactor-db` (key
`REACTOR_AUTOSCALE_K8S_DB_SECRET_KEY`, default `db-url`) -- it is injected
as env and passed via `--db $(REACTOR_DB)`. Multi-host workers need the
workflow binaries available cluster-wide, so bake the reviewed immutable set
into the image or mount a shared `--root` (PVC/NFS) with `readOnly: true` in
the Pod spec. Publish new artifacts outside the worker execution root.

**command.** Total flexibility for anything else (Nomad, systemd, an
internal API). Your spawn command must print the new worker's id to stdout;
that id is substituted for `{id}` in the stop command:

```bash
REACTOR_AUTOSCALE_SPAWNER=command \
REACTOR_AUTOSCALE_SPAWN_CMD='nomad job dispatch -detach reactor-worker | awk "/Dispatched/{print \$3}"' \
REACTOR_AUTOSCALE_STOP_CMD='nomad job stop {id}' \
reactor serve --mode distributed --autoscale ...
```

Off-host spawners are detached, so a worker that crashes on its own keeps
being counted by the controller until the next scale event (the same-host
`process` spawner reaps exits and does not have this gap). That is the safe
direction: the controller never *over*-counts, so it can never exceed your
`MAX`. A crashed worker's lease still expires and its in-flight run
requeues, and as the queue deepens the desired count climbs past the stale
worker and a replacement is spawned. For prompt restart of crashed workers,
also lean on your orchestrator's own health (a Kubernetes `Job`
`backoffLimit`, a process supervisor, etc.).

## Multi-tenancy (fair scheduling, quotas, metering)

Distributed mode is multi-tenant. Every workflow has a `tenant_id` (default
`'default'`), and each run inherits its workflow's tenant. This powers three
things, all managed from the **Tenants** admin page (no API or SQL needed):

**Fair scheduling.** Workers do not claim runs first-in-first-out across the
whole queue. The claim ranks each queued run by its position *within its
tenant* and serves every tenant's oldest run before any tenant's second. One
tenant enqueueing 10,000 runs cannot starve another tenant's single run behind
them -- the shared pool is divided fairly, not by arrival order.

**Quotas.** Each tenant has three caps (0 = unlimited):

| Quota | Enforced | Effect |
| --- | --- | --- |
| `max_concurrent_runs` | at claim | workers stop claiming a tenant's runs once it has this many running |
| `max_queued_runs` | at enqueue | new runs are refused once the tenant's queue is this deep |
| `monthly_run_quota` | at enqueue | new runs are refused once the tenant hits this many runs in the calendar month |

A `disabled` tenant is refused at enqueue and skipped at claim. Refusals
surface as an error to the trigger source (a webhook sender backs off and
retries). The concurrency cap is best-effort under concurrent claimers (it can
briefly overshoot by a batch); fair interleaving, not the cap, is what prevents
starvation. Unknown tenants and zero quotas always pass, so a single-tenant
install is never gated.

**Metering.** Every run writes a `run_usage` row on completion (tenant,
workflow, step count, and two durations: wall-clock `run_seconds` for
diagnostics and `active_seconds` for billing). **Billable compute is active
execution time, not wall clock.** A long wait suspends the run (the subprocess
exits, zero compute) and resumes at `wake_at`, so `active_seconds` (the sum of
step durations) excludes the idle wait. A workflow that sleeps a week bills
seconds, not a week.

**Plans + billing.** A plan (managed on the Plans page) is a tier: a monthly
price, included executions + compute, the operational caps, and overage rates.
Assigning a plan to a tenant copies its caps onto the tenant, so scheduling +
quota enforcement use them directly. **Hard-cap** plans refuse runs past the
included volume (no surprise bill, good for free/unverified tenants);
**soft-cap** plans allow the excess and bill it as overage (executions per 1k,
compute per hour) from the `run_usage` ledger. The Tenants page shows each
tenant's current-month usage and estimated bill. This is the metering + plan
foundation a payment processor (Mollie/Stripe) charges against.

## Per-tenant dashboard, error log, and self-healing

The dashboard is tenant-aware. A dashboard user belongs to a tenant
(`users.tenant_id`); **members see only their own tenant's** workflows, runs,
run timelines, live log tail, and cancel button, while **admins see
everything**. Cross-tenant access returns 404 rather than 403, so a run's
existence is never leaked. Each customer also gets an `/account` page: a
read-only view of their plan, month-to-date usage against the included
allotments, and estimated bill.

The **`/errors`** page is the error log: every failed execution, collected
automatically with the failing step and its error text plus a link to the run
timeline, and a recurring-failure summary that ranks workflows by failure
count so you fix the worst offenders first. It is tenant-scoped like the rest.

The **`/postmortems`** page can close a self-healing loop. When explicitly
enabled, a terminal DLQ run asks Claude to analyse redacted stable metadata and
fixed error summaries; raw Step errors, trigger bodies, and output bodies are
never included. Claude emits a structured post-mortem (root cause, lesson,
recommendation), which Reactor stores in the knowledge corpus. That same corpus
is searchable over MCP, so the next agent that builds or repairs a workflow can
read the accumulated lessons. This external egress is default-off and requires
both `REACTOR_AI_POSTMORTEM_ENABLED=true` and `ANTHROPIC_API_KEY`; the DLQ works
normally without either setting.

## What this is (and isn't) for

Postgres `SKIP LOCKED` scales to high-thousands of jobs/sec, which covers
SMB and mid-market automation comfortably with one simple stack. The
`Queue` claim is a row lease, so if a future workload ever genuinely
outgrows Postgres you can add a streaming backend behind the same seam
without changing the worker or the dispatch path. You are very unlikely to
need that.

Workers are stateless and identical, so "Reactor duplicating itself to
handle load" is just running more `reactor worker` processes (or
containers) against the same database. An autoscaler that starts/stops
workers based on queue depth (`runs WHERE status='queued'`) is a thin
controller on top of this foundation, not a change to it.

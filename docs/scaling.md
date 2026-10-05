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

This is a deployment shape, not a measured throughput promise. In PostgreSQL,
each poll seeks the distinct workflow IDs with currently uncancelled queued
runs through the partial queue index, reads at most its 256-candidate limit
from each such workflow, then ranks those candidates fairly by tenant. That
avoids ranking one workflow's deep backlog and makes discovery depend on
currently queued workflows instead of every workflow that has ever queued.
Migration 0065's older append-only workflow hint is still written for mixed
old/new daemon compatibility, but the current claim query no longer reads it;
retire that table and trigger only in a coordinated later cutover. The planner
may still choose an older general workflow index and scan filtered history;
malformed older rows with a mismatched tenant can also require extra index
reads before the candidate limit is met. Tenant-cap checks still count running
rows.
`SKIP LOCKED` prevents workers from waiting on one another's row locks, and a
bounded contention retry can reach later unlocked work. Measure queue age,
claim latency, database pool waits, WAL/IO, and completed runs per second under
the intended tenant mix before increasing worker count or introducing a broker.

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
- While a run executes, the worker **heartbeats** its lease. Each renewal has
  a deadline no longer than one third of the configured lease TTL (capped at
  five seconds). Under normal scheduling, a missed renewal signals workflow
  cancellation before the old lease expires, including when the database call
  itself fails to return after its deadline. External calls still need
  idempotency keys because cancellation cannot undo a committed side effect.
  If a worker dies, its lease expires and the elected `serve` leader or any
  worker's reaper requeues the run
  (`status` back to `queued`). The supervisor reuses completed journaled
  steps; external writes that committed before their Step result was saved
  still need stable idempotency keys. Each journal reaper transaction handles
  at most 128 expired leases. The leader makes an immediate recovery pass on
  acquiring leadership, before it starts autoscaling, then runs recovery even
  when no workers exist. One leader pass makes at most eight capped calls;
  remaining expired leases are revisited after one second. This lets a
  scale-to-zero fleet recover runs stranded by a total worker crash without
  one unbounded transaction holding the queue.
- Worker-owned step starts and outcomes, exact dead-letter repair,
  finalization, artifact-fence terminalization, redrive repair, block receipts,
  and secret-access audits lock the exact lease generation and recheck its
  deadline immediately before committing. A worker delayed past
  expiry rolls back even if the reaper has not visited its row; the reaper then
  recovers the run. Keep worker clocks synchronized, because lease deadlines
  are issued and checked by application hosts.
- Workers also heartbeat their fleet-registry row every 8 seconds. Each write
  has a two-second deadline; a stuck driver stops new admission and begins a
  drain. The reaper removes rows that have been silent for 30 seconds, so
  crashed workers disappear from the registry and its index instead of
  accumulating forever;
  the threshold matches the dashboard's active-worker window. A worker must
  publish its initial heartbeat before it can claim queue rows. One or two
  transient heartbeat write failures are logged and tolerated; after three
  consecutive failures the worker stops admitting work and drains so an
  invisible worker cannot retain leases indefinitely.
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
reactor serve --mode distributed --db postgres://user:pw@db/reactor --root /var/lib/reactor \
  --worker-artifact-root /mnt/reactor-artifacts

# as many workers as you need, same DB + read-only immutable artifact tree
reactor worker --db postgres://user:pw@db/reactor --root /var/lib/reactor-worker-1 \
  --artifact-root /mnt/reactor-artifacts --concurrency 16
reactor worker --db postgres://user:pw@db/reactor --root /var/lib/reactor-worker-2 \
  --artifact-root /mnt/reactor-artifacts --concurrency 16
```

Each worker runs up to `--concurrency` runs at once (1–64; default = Go
scheduler parallelism, capped at 64). Invalid CLI or environment values fail
startup before a worker can advertise capacity or claim runs.
To add capacity, start more workers; to remove it, stop them (SIGINT/SIGTERM
drains in-flight runs first).
Start a serving daemon or run `reactor migrate` before adding workers. A worker
checks every embedded schema version without applying migrations, so a scaled
worker does not need DDL permission and refuses a missing or mismatched schema.
It initializes only execution dependencies; normal worker startup does not
seed knowledge or create authoring files under `--root`. An explicitly enabled
AI post-mortem generator still needs a writable shared knowledge directory;
leave that feature disabled on read-only workers until its output is routed
through a separate writable service.
When workflow artifacts live on a separate read-only mount, set
`--artifact-root` (or `REACTOR_WORKER_ARTIFACT_ROOT`) to the directory containing
`workflows/`. The worker checks that directory before connecting to the queue.
The executable and retained-source proof both use that same tree; `--root`
remains the worker's private state directory.
Mount that same tree read-only at the same absolute path in every serving
daemon. Set `reactor serve --worker-artifact-root` (or
`REACTOR_WORKER_ARTIFACT_ROOT`) even with manually started workers and no
autoscaler. The daemon verifies each exact version on that tree before enable
and queue admission; the worker independently verifies the bytes before use.
The setting is optional for legacy same-tree deployments, so an unset value
does **not** prove that a separate worker has the reviewed artifact.
If shutdown arrives after a queue claim but before that run starts, the worker
does not launch it during the drain window. It returns that exact, unstarted
lease to the queue so another worker can claim it promptly. If the database is
unavailable during shutdown, lease expiry and the reaper remain the recovery
path.

### Config

| Flag / env | Default | What |
| --- | --- | --- |
| `--mode` / `REACTOR_MODE` | `local` | `local` or `distributed` |
| `--concurrency` / `REACTOR_WORKER_CONCURRENCY` | Go scheduler parallelism, capped at 64 | max concurrent runs per worker (1–64) |
| `--lease-ttl` | `60s` | lease validity (minimum `1s`); heartbeated while running, reaped if a worker dies |
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

Migration 0056 also changes workflow source proof. Existing version rows keep
their legacy policy, while new rows require a source-manifest pin. Quiesce
workflow authoring while applying it and upgrade every authoring daemon before
reopening creation or revision: an older daemon can insert a new unpinned row
that the upgraded execution boundary correctly refuses to run. Verify a newly
built workflow and one retained legacy workflow before enabling normal traffic.

## Autoscaling (optional)

Workers are stateless and identical, so "Reactor duplicating itself to
handle load" is just running more `reactor worker` processes. The daemon
can do that for you: pass `--autoscale` (or `REACTOR_AUTOSCALE=1`) to a
`serve --mode distributed` instance and the **leader** runs a controller
that spawns and stops workers to track queue depth.

```bash
REACTOR_DB_URL=postgres://... reactor serve --mode distributed --autoscale --root /var/lib/reactor
```

Every 15s the controller counts **currently claimable** queued runs up to the
point needed for its maximum target, then computes a baseline worker count =
`ceil(claimable / queue_per_worker)`, clamped to `[min, max]`. Disabled workflows
or tenants, cancellation requests, tenants already at their concurrency cap,
and runs whose stored tenant differs from their workflow owner do not trigger
scale-up; workers enforce the same policies again when claiming. The dashboard's
raw queue depth and oldest age continue to include blocked-but-retained backlog,
so operators can see it without spawning workers that cannot process it.
On PostgreSQL, a target threshold of up to 256 returns at most that many eligible
queued rows per indexed workflow before tenant-fair ranking. Larger thresholds use an
exact scan rather than undercounting. The exact `reactor_queue_claimable_depth`
metrics gauge also groups all eligible queued rows; it counts running rows only
for capped tenants with queued work, using the tenant/status index. That exact
queued scan is still proportional to the eligible backlog, and each metrics
scrape runs it. Measure probe latency and database pool waits at the intended
queue size before shortening the controller interval, increasing scrape
frequency, or raising the worker maximum. Historical rows with mismatched
run/workflow tenant IDs stay queued and need operator review and correction;
they cannot execute as another tenant.

To find those retained rows in PostgreSQL, inspect a bounded page of IDs before
deciding whether each run should be repaired or cancelled. Do not rewrite its
tenant ID without confirming the original dispatch and payload owner:

```sql
SELECT r.id, r.workflow_id, r.tenant_id AS run_tenant,
       w.tenant_id AS workflow_tenant
FROM runs r JOIN workflows w ON w.id = r.workflow_id
WHERE r.status = 'queued' AND r.tenant_id <> w.tenant_id
ORDER BY r.created_at, r.id LIMIT 100;
```
When a queued run is waiting and all recently heartbeating worker slots are
occupied, it can add one managed worker even if the queue is shorter than
`queue_per_worker`. An unavailable capacity probe falls back to the queue-depth
target; zero recently heartbeating capacity is not proof of saturation. The
capacity probe is fleet-wide and does not identify which managed worker owns
each heartbeat, so a newly launched worker may still be starting while an
unrelated worker makes the aggregate slots look occupied.
The controller moves **one worker per tick** toward the target. The defaults are deliberately
safe, because a self-replicating system must never run away:

- **`REACTOR_AUTOSCALE_MAX`** (default `4`) caps the workers in one managed
  fleet. Built-in Docker/Kubernetes inventory counts that fleet across leader
  restarts before any new worker is spawned. The default same-host process
  spawner cannot inventory old processes after a serve crash; its child
  workers drain when the inherited parent-liveness pipe closes, but a short
  overlap with replacements is possible during that drain window.
- Scale-up is paced by a cooldown, so even sustained load ramps one worker
  at a time rather than bursting.
- Scale-down only happens after both the queue and currently running work have
  stayed empty for a cooldown (no flapping or stopping a worker while it owns
  a run). A failed worker, queue, or running-work probe holds scale-down and
  restarts the idle cooldown when observation resumes.
- **`REACTOR_AUTOSCALE_MIN`** (default `0`) lets the pool scale to zero
  when idle (no workers, no cost) and back up on the next burst. The elected
  leader requeues expired claims independently of workers, so a complete
  worker crash exposes that work to this queue-depth signal again.

| Env | Default | What |
| --- | --- | --- |
| `--autoscale` / `REACTOR_AUTOSCALE` | off | enable the autoscaler (leader, distributed only) |
| `REACTOR_AUTOSCALE_MIN` | `0` | minimum workers (0 = scale to zero) |
| `REACTOR_AUTOSCALE_MAX` | `4` | managed fleet cap; process crash drain may briefly overlap replacement workers |
| `REACTOR_AUTOSCALE_QUEUE_PER_WORKER` | `20` | claimable queued runs per worker before adding one |
| `REACTOR_WORKER_CONCURRENCY` (process/Docker autoscaler) | Go scheduler parallelism, capped at `64` | simultaneous runs per spawned worker; explicit value must be 1–64 |
| `REACTOR_AUTOSCALE_FLEET_ID` | unset | required for built-in Docker/Kubernetes spawners; stable, unique label for one managed fleet |

When distributed autoscaling is enabled, `MIN`, `MAX`, and
`QUEUE_PER_WORKER` must be valid integers. `MIN` must be nonnegative,
`MAX` and `QUEUE_PER_WORKER` must be positive, and `MIN` cannot exceed
`MAX`. Reactor rejects an invalid or empty explicit setting before the
daemon becomes ready; it does not silently replace a configured fleet cap
with the default.
The process and Docker spawners also reject an invalid or empty explicit
`REACTOR_WORKER_CONCURRENCY` before serving traffic. Their bounded default
uses the serving process's configured Go scheduler parallelism; set an
explicit value when worker CPU or memory allocation differs from the daemon.

The dashboard home shows the live fleet (active workers + total
concurrency + raw queue depth) so you can watch it work. `/metrics` exposes
both `reactor_queue_depth` (raw retained backlog) and
`reactor_queue_claimable_depth` (the autoscaler input), alongside
`reactor_worker_count` and `reactor_worker_capacity`. A corresponding probe
status of `0` and gauge value of `-1` mean the database read failed, rather
than that the queue is idle.

### Where workers run (the spawner)

By default the autoscaler spawns workers as **child processes on the same
host** -- zero setup, bounded by that one box. To scale across a fleet,
point it at an orchestrator with `REACTOR_AUTOSCALE_SPAWNER`. Reactor does
not link the Docker or Kubernetes SDKs; it shells out to your own CLI, so
one mechanism covers every cluster manager and pins no client version.
Each process-spawned worker watches an inherited pipe. If its serving parent
exits abruptly, kernel EOF cancels new admissions and starts the worker's
drain; the configured drain timeout cancels in-flight runs, and the normal
lease reaper recovers interrupted claims. Manually started and
orchestrator-managed workers do not use this parent contract.

| `REACTOR_AUTOSCALE_SPAWNER` | Spawns a worker by | Needs |
| --- | --- | --- |
| `process` (default) | re-execing this binary as `reactor worker` | nothing |
| `docker` | `docker run -d <image> worker ...` | `REACTOR_WORKER_IMAGE`, a reachable Docker daemon |
| `kubernetes` | `kubectl create` of a worker `Job` | `REACTOR_WORKER_IMAGE`, database and master-key Secrets, an artifact PVC, a working `kubectl` context |
| `command` | running your own shell commands | `REACTOR_AUTOSCALE_SPAWN_CMD` (+ `_STOP_CMD`) |

All four are driven by the same controller and the same `MIN`/`MAX`/cooldown
safety. For Docker and Kubernetes, set `REACTOR_AUTOSCALE_FLEET_ID` to a stable
1–63 character value using lowercase letters, digits, and internal hyphens.
Use the same value on every leader replica and after restart, and a different
value for another worker fleet. Reactor labels new workers with it, inventories
the substrate before startup and every scaling decision, and adopts only exact
matches. The label is an ownership identifier, not a secret. CLI list/get or
ownership-probe errors hold scaling; a stop checks the current label again.
The configured maximum applies per fleet ID, not across separately labelled
fleets or manually started workers. Inventory is bounded to 30 seconds and
256 KiB of CLI output; a very large or slow fleet may hold scaling until its
inventory can be read within those limits. Benchmark and tune the substrate
before raising `MAX` substantially.

Before upgrading an existing Docker/Kubernetes autoscaler, drain or remove its
old, unlabelled `reactor-worker` containers or `app=reactor-worker` Jobs. Their
ownership cannot be established after a restart, so Reactor holds scaling
while any are present rather than risking an overshoot. Likewise, drain the
old fleet before changing `REACTOR_AUTOSCALE_FLEET_ID`: workers with the old
label are a distinct fleet and are deliberately never adopted or stopped by
the new one. The Docker CLI needs container list/inspect/stop/remove access; the
Kubernetes identity needs Job list/get/create/delete access in the selected
namespace. The custom command spawner has no general inventory or ownership
contract, so its tracked maximum still covers only its current controller
lifetime; provide an external capacity fence for restart recovery.
For Kubernetes, the ownership `get` and `delete` are separate API calls: an
actor with Job write access could replace the same-named Job between them.
Restrict that access and isolate the namespace. The current CLI stop path does
not use a Kubernetes UID precondition.

**docker.** The worker container reads the configured `REACTOR_DB_URL` and
loaded vault `REACTOR_MASTER_KEY` from its environment, including when the
server loaded the key from a file. Neither value is placed in Docker command
arguments. Docker daemon administrators can still inspect container
environment, so restrict daemon access accordingly. Same-host child workers
receive both values through their environment instead of process arguments.
Built-in Docker scale-down uses `docker stop --signal SIGTERM` with a grace period longer than
the worker's configured drain timeout; `--rm` removes the container after it
exits. This matters because a new claim can arrive after the controller's
idle observation. If the worker does not exit by the grace deadline, Docker
sends SIGKILL and the normal lease reaper recovers unfinished runs. A terminal
container is removed with non-forced `docker rm` after an exact fleet ownership
check. Custom command spawners must provide their own graceful stop behavior.
Workers need the compiled workflow binaries under `--artifact-root` when set,
or under `--root` otherwise. For a production fleet, provide the reviewed
artifact set through a read-only mount (or an
atomic, checksum-verified local distribution) and set the DB network with
`REACTOR_AUTOSCALE_DOCKER_ARGS`. A bind-mounted `--root` must be owned by the
Reactor container UID and have mode 0700; the image's state-root permissions
do not change a host bind mount. For example:

```bash
REACTOR_AUTOSCALE_SPAWNER=docker \
REACTOR_AUTOSCALE_FLEET_ID=reactor-prod \
REACTOR_WORKER_IMAGE=registry.example.com/reactor:latest \
REACTOR_DB_URL=postgres://... \
REACTOR_AUTOSCALE_DOCKER_ARGS="-v /var/lib/reactor:/var/lib/reactor:ro -v /mnt/reactor-artifacts:/mnt/reactor-artifacts:ro --network host" \
reactor serve --mode distributed --autoscale --root /var/lib/reactor \
  --worker-artifact-root /mnt/reactor-artifacts
```

The Docker artifact bind must expose the same absolute path to the container
as the serving daemon sees. Reactor passes the configured path as the worker's
`--artifact-root`; a missing mount makes the worker refuse startup. Without a
configured serving-daemon artifact root, Docker workers may still verify their
own bytes, but daemon-side enable, preflight, and queue admission cannot prove
their artifact copy is ready.

**kubernetes.** Each scale-up `kubectl create`s a `Job` (`generateName:
reactor-worker-`, `ttlSecondsAfterFinished` so finished Jobs are collected);
scale-down deletes it with foreground cascading deletion and waits for its
Pod to disappear before releasing the capacity slot. A timed-out delete keeps
the Job tracked for reconciliation. Set `REACTOR_AUTOSCALE_K8S_NAMESPACE` (default
`default`). Point `REACTOR_AUTOSCALE_K8S_DB_SECRET` at an existing Secret
(key `REACTOR_AUTOSCALE_K8S_DB_SECRET_KEY`, default `db-url`) and
`REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET` at a Secret holding the 64-hex vault
master key (key `REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET_KEY`, default
`master-key`). Set `REACTOR_AUTOSCALE_K8S_ARTIFACT_PVC` to the existing PVC
whose root contains the reviewed `workflows/` tree, and set
`REACTOR_WORKER_ARTIFACT_ROOT` to a clean absolute path shared by the serving
daemon and worker container (for example `/mnt/reactor-artifacts`). Mount the
same PVC read-only at that path in every serving daemon as well. The daemon
refuses startup when its mount lacks a real `workflows/` directory, and checks
each exact artifact and retained source on that tree before queue admission.
The generated Job mounts the PVC at that path with `readOnly: true` and passes
the same path to the worker.
Set `REACTOR_WORKER_CONCURRENCY` and all four Kubernetes resource variables
before enabling this spawner; there are no CPU or memory defaults inherited
from the serving daemon. CPU values are integer millicores (`1000` = one CPU),
and memory values are integer MiB. Requests and limits appear on the worker
container in every generated Job:

| Variable | Accepted range | Meaning |
| --- | --- | --- |
| `REACTOR_WORKER_CONCURRENCY` | 1–64 | Maximum workflow runs admitted simultaneously by one worker Pod |
| `REACTOR_AUTOSCALE_K8S_CPU_REQUEST_MILLI` | 10–128000 | CPU requested from the scheduler |
| `REACTOR_AUTOSCALE_K8S_CPU_LIMIT_MILLI` | 10–128000 | Container CPU limit; must be at least the request |
| `REACTOR_AUTOSCALE_K8S_MEMORY_REQUEST_MIB` | 128–1048576 | Memory requested from the scheduler |
| `REACTOR_AUTOSCALE_K8S_MEMORY_LIMIT_MIB` | 128–1048576 | Container memory limit; must be at least the request and `256 + 512 × REACTOR_WORKER_CONCURRENCY` MiB |

The memory floor reserves the supervisor's default 512 MiB allowance for
each active workflow and 256 MiB for the worker process. It is a startup
sanity check, not evidence that a particular workload fits. Set requests and
limits from measured peak resident memory, CPU, and expected concurrency;
allow for sidecars and other Pods when sizing the node pool. Setting memory
request below its limit permits node overcommit, so pressure can still evict
workers. Increasing the limit does not increase queue throughput by itself;
validate the database connection budget and workload behavior before raising
concurrency or the fleet maximum. A deployment upgraded from an older Reactor
version must supply these values before its Kubernetes autoscaler can start.

Choose storage that allows the planned worker Pods to mount the PVC across
their nodes.
The mount must not shadow the private `--root` directory. The worker refuses
startup if the mounted `workflows/` directory is missing or symlinked. It reads
`REACTOR_DB_URL` and `REACTOR_MASTER_KEY` from the named Secrets; neither value
appears in the manifest or command arguments. Set the worker's private `--root`
up as a writable mode-0700 directory owned by the Reactor UID. The packaged
image provides that mode for its own state root; bind-mounted roots also need
mode 0700 and ownership of the Reactor UID. The Job passes the daemon's
configured drain timeout to the worker and gives the Pod that timeout plus
10 seconds to stop after SIGTERM. Publish each new immutable artifact and its
retained source into the PVC before dispatching runs pinned to that digest.
Enable `--mcp-allow-artifact-publication` on the HTTP daemon and run a separate
publisher process against the same Postgres database:

```bash
reactor artifact-publisher \
  --db "$REACTOR_DB_URL" \
  --source-root /mnt/reactor-authoring \
  --destination-root /mnt/reactor-artifacts
```

The publisher claims exact tenant/workflow/version/digest requests from
`reactor_publish_workflow_artifact`, renews its lease while copying, verifies
the artifact, retained source, and visual DAG on both roots, then records a
`published` receipt. An AI client should poll
`reactor_get_artifact_publication` before enabling or preflighting. The
publisher needs read access to the durable authoring `workflows/` tree and a
**writable** mount of the worker PVC. Mount only that `workflows/` subtree into
its source root; it does not need the authoring daemon's `master.key`, vault
access, HTTP token, or a listener. Serving daemons and workers retain read-only
mounts of the worker PVC. The authoring tree must be durable and visible to
the publisher; a queue receipt cannot distribute bytes that exist only on an
ephemeral authoring Pod. Keep one authoritative authoring writer unless the
shared filesystem's slug locking has been validated across nodes.
Keep one publisher replica unless the worker PVC also supports reliable
cross-node file locks; the Postgres queue permits multiple claimers, but the
destination namespace still relies on the registry's slug lock while writing.
Requests retry with bounded backoff and become terminal after ten attempts.
After repairing the reported failure, an authenticated admin may use
`reactor_requeue_artifact_publication` with the exact receipt ID and digest;
the journal refuses requeue if a different workflow version is now current.

The exact-version manual command remains available for controlled repair:

```bash
reactor workflow mirror \
  --db "$REACTOR_DB_URL" \
  --root /var/lib/reactor \
  --destination-root /mnt/reactor-artifacts \
  --tenant acme --slug customer-onboarding --version 3
```

Both paths refuse an existing destination with different bytes or ownership.
The publisher's write access is a separate operational privilege and should
not be given to worker Pods. Publication alone does not mark a workflow
reviewed, enable it, or start a run. A publisher crash can leave
an unused `.mirror-source-*` staging directory under the exact artifact
digest; the command refuses further stages after eight until an operator
inspects and removes the abandoned ones. When `--worker-artifact-root` is
configured, MCP preflight reports `worker_artifact_ready` and refuses to call a
workflow dispatchable while the mirrored version is missing or invalid. MCP
review exposes that publication state, and both MCP and dashboard enable
actions refuse an unverified exact version on the daemon-visible worker tree.
The enable check is point-in-time; dispatch and workers repeat the artifact
proof. Without the setting, those daemon-side checks verify only the authoring
tree; they do not certify an independent worker copy. This admission check
depends on the daemon and workers mounting the same tree; pointing them at
different volumes breaks the deployment contract.
Before rolling a worker image over an existing Docker named volume or
Kubernetes persistent volume used for the private `--root`, inspect its owner
and mode and repair them to the Reactor UID and 0700. Image permissions do not
change directory metadata retained by an existing volume.

**command.** Total flexibility for anything else (Nomad, systemd, an
internal API). Your spawn command must print the new worker's id to stdout;
that id is substituted for `{id}` in the stop command:

```bash
REACTOR_AUTOSCALE_SPAWNER=command \
REACTOR_AUTOSCALE_SPAWN_CMD='nomad job dispatch -detach reactor-worker | awk "/Dispatched/{print \$3}"' \
REACTOR_AUTOSCALE_STOP_CMD='nomad job stop {id}' \
reactor serve --mode distributed --autoscale ...
```

Off-host spawners are detached. Before each scaling decision, the built-in
Docker spawner inspects its tracked containers and the Kubernetes spawner gets
its tracked Jobs. An exited/dead container or terminal Job is cleaned up and
its slot released; a confirmed missing container or Job releases its slot
directly. A probe timeout, permission error, malformed response, or ambiguous
"not found" response holds all scaling for that tick. This check is bounded
by the spawner's command timeout (30 seconds by default), so an unavailable
orchestrator cannot trigger a replacement burst. A crashed worker's lease
still expires and its in-flight run requeues.

The `command` spawner has no general way to prove that a detached worker has
exited, so stale handles can still occupy `MAX`; use an orchestrator health
policy and restart the autoscaler after operator recovery if necessary. A
launcher that returns no safe worker ID also keeps an unaddressable slot
counted rather than risking a duplicate worker. A launcher process that starts
but exits unsuccessfully or times out might also have created a worker before
failing, so Reactor reserves an unaddressable slot for that attempt. This can
hold capacity even when no worker was created; inspect the orchestrator and
resolve any orphan before restarting the autoscaler. A launcher executable
that cannot start does not reserve a slot. Custom-command handles are only in
memory: after a Reactor server restart, those detached workers are not
rediscovered. Keep the autoscaler on one leader and drain or externally
inventory custom-command workers during a server restart to preserve the
intended fleet cap. The built-in Docker and Kubernetes spawners use their
stable fleet label to rediscover workers after a restart.

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
| `max_concurrent_runs` | local admission + distributed claim | local runs are refused before INSERT at the cap; workers stop claiming queued runs once the tenant has this many running |
| `max_queued_runs` | at enqueue | new runs are refused once the tenant's queue is this deep |
| `monthly_run_quota` | at enqueue | new runs are refused once the tenant hits this many runs in the calendar month |

A `disabled` tenant is refused at enqueue and skipped at claim. Refusals
surface as an error to the trigger source (a webhook sender backs off and
retries). PostgreSQL claims lock each affected tenant policy row and recheck
capped tenants' running counts before changing queued rows to running, so
simultaneous claimers share one exact concurrency budget. Capped tenants take
an exclusive lock; unlimited tenants take a shared policy lock so their
independent claim batches can proceed concurrently. Locks are taken in sorted
tenant order. Fair interleaving prevents starvation independently of the cap.
Unknown tenants and
zero quotas always pass, so a single-tenant install is never gated.

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

In distributed Postgres mode, dashboard and MCP analytics calculate succeeded
run averages and p95 in SQL, and group the seven-day activity strip in SQL.
The daemon receives aggregate rows instead of loading every retained run
duration or recent event into memory. The seven-day tenant query has a
`(tenant_id, started_at)` index. The exact p95 still scans and sorts retained
succeeded history in Postgres, and the dashboard issues several independent
queries, so concurrent updates can briefly make the headline and per-workflow
figures disagree. Query latency depends on retention, indexes, hardware, and
tenant distribution; measure it against the intended production workload
before setting an SLA.

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

Postgres `SKIP LOCKED` supports concurrent workers without a second broker,
but Reactor has no verified jobs-per-second capacity result yet. A defensible
capacity claim needs an isolated Postgres load run that includes dispatch,
tenant admission, claims, workflow subprocesses, step journaling, connector
egress, retention, analytics, and worker failure/recovery. The `Queue` claim
is a row lease, leaving room for a different backend if a measured workload
eventually needs one.

Choose any additional datastore by the measured bottleneck, not by a general
SQL-versus-NoSQL label. The fair-share claim ranks a bounded slice per indexed
workflow by tenant and counts running runs for capped tenants on each claim;
many indexed workflows, a poor query plan, or many idle workers can make that
query expensive even when Postgres itself has headroom.
Measure claim p95/p99 latency, query plans and buffer reads, lock waits, queue
age (`reactor_queue_oldest_age_seconds`), journal write latency, and database CPU/IOPS while increasing workers and
backlog. First tune the claim query, indexes, polling, connection pool, and
retention against the observed plan. If immutable event ingestion then exceeds
the transactional journal's sustainable write rate, evaluate a dedicated
stream or broker with an explicit outbox and recovery design; it does not
replace Postgres as the run/lease/credential source of truth. If historical
dashboard aggregates dominate instead, evaluate rollups or a columnar
analytics replica. Neither alternative is justified by worker count alone.

For a safe first PostgreSQL claim-path diagnostic, use a **dedicated idle test
database** whose name contains `test` and run the opt-in bounded probe:

```bash
REACTOR_TEST_POSTGRES_URL='postgres://.../reactor_queue_test' \
REACTOR_TEST_POSTGRES_QUEUE_PROBE=1 \
go test ./internal/runtime/journal -run '^TestPostgresQueueClaimBoundedProbe$' -count=1 -v
```

It migrates that test database, refuses an already active queue, inserts at most
1,160 synthetic queued runs, and removes them afterward. It records an `EXPLAIN
(ANALYZE, BUFFERS)` for the fair candidate query plus one actual 16-slot claim
and three blocked-backlog polls. Assertions cover noisy/quiet tenant fairness,
disabled tenants, concurrency caps, and expired-lease replacement at the real
claim boundary. The plan and individual elapsed times are diagnostic samples,
not a throughput or p95/p99 result; no PostgreSQL measurement is currently
recorded for the repository.

The PostgreSQL claim locks each selected run exclusively and its workflow in
shared mode. Distinct runs of one workflow can therefore be claimed by
different workers while an enable/disable update still waits for claims to
finish. `TestPostgresClaimSharesWorkflowLockAcrossDistinctRuns` checks this
at the real claim boundary when `REACTOR_TEST_POSTGRES_URL` points to an idle,
dedicated test database. This removes a workflow-row lock conflict; its
throughput effect still needs the isolated load run described above.

Each distributed worker logs a `worker: claim latency summary` every minute
and once at shutdown. The counters and fixed
duration buckets are cumulative for that worker process and include empty
polls, claim errors, and cancelled polls separately. Durations cover the full
claim call, including connection-pool wait, candidate selection, row locks,
tenant admission, lease writes, and commit; they are not a measurement of the
candidate SQL alone. Collect worker logs across the fleet to estimate latency
percentiles from the bucket upper bounds. Each summary also reports this
worker's SQL pool size, use, and cumulative connection wait count/duration;
compare their deltas with claim latency before attributing delay to PostgreSQL
query work. The daemon's `/metrics` queue age, depth, and pool gauges describe
its own process and do not report worker claim latency.

Workers are stateless and identical, so more `reactor worker` processes or
containers add execution slots against the same database. The optional
leader-only autoscaler above already adjusts that fleet using queue depth
while protecting running work during scale-down. Built-in Docker and
Kubernetes workers are checked against their substrates each tick; custom
off-host spawners still need an orchestrator health policy and a recovery path
for stale detached IDs.

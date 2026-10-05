# Operations

## Install paths

| Path             | When                                                    |
| ---------------- | ------------------------------------------------------- |
| `brew install`   | macOS or Linux workstation development (matching SDK and Go included) |
| `.deb` package   | Debian / Ubuntu servers (systemd-managed)               |
| `.rpm` package   | RHEL / Fedora servers (systemd-managed)                 |
| `docker run`     | Container-first deployments + ephemeral CI              |
| `docker-compose` | Development/single-node SQLite evaluation                |
| systemd unit     | Manual bare-metal install (built from source)           |

The `v*` release workflow builds binaries, `.deb`/`.rpm` packages, and a
release-matched SDK archive used by the Homebrew formula. It does not currently
build a Docker image or sign/attest release artifacts; verify the exact image
and release provenance separately before promotion. The Homebrew wrapper pins
`REACTOR_SDK_REPLACE` to its installed SDK module and adds its Go dependency to
`PATH`, so MCP authoring can compile offline. Native Linux packages still
require an operator-installed Go 1.26.5+ toolchain.
The release attaches the rendered Homebrew formula, but tap publication and
automatic formula upgrades are not configured yet.

See `deploy/README.md` for the Docker + systemd walkthroughs and
`packaging/` for the Homebrew formula template + nfpm config.

## Local first boot

This is the SQLite development path. Local Reactor resumes interrupted work from
durable Step, retry-attempt, and DLQ-repair checkpoints, but it remains a
single-process recovery topology rather than leased high availability. It is
not approved for production Hash signing. The required bridge topology is
described in [Scaling](/docs/scaling) and
[Hash e-signature bridge](/docs/hash-esign-bridge).

```bash
reactor init --root /var/lib/reactor
reactor migrate --db sqlite:///var/lib/reactor/reactor.db
# Add an admin via:
echo -n 'changeme' | sha256sum | awk '{print $1}'  # paste into REACTOR_BASIC_AUTH_PASSWORD_SHA256
reactor serve --root /var/lib/reactor --db sqlite:///var/lib/reactor/reactor.db
```

## Backup

For a stopped SQLite instance, the state directory is the backup target:

```bash
tar -czf reactor-$(date +%F).tar.gz /var/lib/reactor
```

New run trigger input and metadata are encrypted after migration 0060 and a
keyed daemon initializes the wrapped journal data key. Migration 0061 extends
that protection to new step output and error fields; migration 0063 covers new
dead-letter error and payload copies; migration 0064 covers new persisted
run-log lines; migration 0066 covers new command-run output and error fields;
migration 0067 covers new signal tokens/payloads; migration 0068 covers new
notification-channel configuration. Historical version-zero run, step,
dead-letter, log, command-run, signal, notification-channel, and command
definition fields can still be plaintext in the database. Migration 0070 covers
new authored command definitions when the keyed daemon is initialized; 0071
adds the explicit bounded historical-definition backfill described below.
storage and backup encryption remain necessary. Losing
`master.key` makes vault credentials and encrypted execution data
unrecoverable unless the matching prior master key is still available. For a
keyed database, `reactor dlq list` and `reactor dlq show` load the existing
wrapped journal key from `--root`/`master.key` or `--master-key-file`; these
read commands do not initialize a new key. For a
PostgreSQL deployment, back up PostgreSQL with a database-native consistent
mechanism and separately preserve the matching `master.key`, reviewed workflow
source/DAG, compiled artifacts and checksums, and deployment configuration. A
tar archive of `<root>` does not contain the PostgreSQL database and is not a
complete production backup. Restore a recovery generation into isolation and
prove vault decryption, exact run-input and step-output replay, authenticated
run-log and dead-letter reads, dead-letter redrive, and workflow execution before
accepting it.

The vault can re-encrypt on master-key rotation. The journal keeps the same
random data key and rewraps it under the new master when a keyed daemon starts
with `REACTOR_MASTER_KEY_PREVIOUS`; it does not re-encrypt every run. Workers
must receive both current and previous keys during that window. Retain the
previous key with every backup generation that still needs it, and verify a
restored copy with the matching key before retiring that previous key.

For an upgrade to 0060, stop old daemon, worker, and MCP-dispatch binaries,
apply the migration, and start keyed daemons/workers with the same current
master key. After the first keyed startup, the database refuses version-zero
run inserts, so old binaries cannot silently persist a new plaintext run.
Existing version-zero rows remain readable and plaintext; this migration does
not backfill them. Schema rollback to 0059 refuses while any version-one run
exists, because dropping the wrapped key or version marker would strand data.

For an upgrade to 0061, drain active runs before switching workers and MCP
readers. Apply the migration, start only keyed 0061 binaries, and verify
exact step replay and bounded output export against synthetic data before
reopening admission. The database rejects old-binary plaintext step inserts
and outcome updates after key initialization; those old workers would fail
rather than complete their attempts. Existing version-zero step rows remain
plaintext and readable. Schema rollback to 0060 refuses while any version-one
step row or the wrapped journal key exists.

For 0062, quiesce new OAuth connections and drain old daemon, worker, and
command-runner binaries before approving an existing connection for broker-only
use. Old binaries ignore the new mode column and running children can retain
tokens already released to them. Upgrade every runtime, verify the exact
deployed image, then test a reviewed connection's host-brokered GET and raw
token denial with synthetic credentials before reopening traffic. Existing
generic connections remain explicitly grandfathered raw until reviewed; new
generic connections wait for review.

For 0063, drain old DLQ writers and start keyed daemons and workers after the
migration. Verify a new encrypted failure, bounded tenant read, and exact
redrive in staging. Once the journal key exists, the database rejects old
plaintext DLQ writes and the schema cannot be rolled back while that key or
encrypted DLQ rows remain. Historical DLQ rows still need a separate backfill
and retain their existing storage and backup controls.

For 0064, drain old daemon, worker, dashboard, and MCP reader processes before
applying the migration. Start only keyed 0064 binaries and verify a synthetic
finished-run log and a scheduled artifact-fence marker can be read after
restart. The database rejects old-binary plaintext log
inserts once the journal key exists. Historical rows remain plaintext until a
separate backfill, and schema rollback refuses while the key or encrypted log
rows exist. Full dashboard log reads still have no row-count page limit; use
retention and bounded MCP pages for large retry histories.

For 0066, drain command-runner workers and old dashboard/MCP readers before
applying the migration. Start only keyed binaries and verify a synthetic
command run's live output, final step/attempt records, parent error, and
diagnostic byte page after restart. A daemon without the master key cannot
start its keyed journal, and unkeyed journal readers/writers fail when they
touch version-one command data; old binaries cannot persist new plaintext
output/error fields after first-key initialization. Previously stored
version-zero command-run output and errors remain plaintext and readable;
0066 does not backfill them. Schema rollback refuses while the journal key or
any encrypted command field exists. Protect database backups and account for
both historical plaintext and authorized decrypted output views during the
cutover.

For 0067, drain old signal writers and readers, then start keyed daemons and
workers. Verify a synthetic signal's token lookup and payload delivery after
restart. Existing version-zero signal rows remain plaintext; 0067 does not
backfill them. The database rejects new plaintext signal rows after key
initialization and refuses rollback while keyed signal rows or the journal
key exist.

For 0068, drain old notification writers, notifier workers, dashboard readers,
and MCP processes before migration. Start keyed binaries and verify a synthetic
channel's encrypted database row, notifier lookup, and metadata-only MCP list
after restart. The database rejects old-binary plaintext inserts and config
updates after key initialization. Historical version-zero channel configs
remain plaintext; 0068 does not backfill them. Full reads of oversized legacy
config fail closed while metadata inventory remains available. Schema rollback
refuses while the journal key or any encrypted channel row exists. Preserve the
matching master key with database backups.

For 0070/0071, drain older command runners, daemon/MCP readers, and command
authoring processes before migration or backfill. After keyed startup and a
consistent database backup, run one bounded batch at a time:

```bash
reactor payload backfill-command-definitions --db "$REACTOR_DB_URL" --root /var/lib/reactor --limit 32
```

Repeat until the command reports `Encrypted 0 ... more=false`. It loads the
existing wrapped journal key and refuses to initialize one. Each transaction
seals at most 32 historical definitions, preserving their exact-version read
and review digest. Invalid or oversized legacy JSON aborts its batch without
partial conversion; the error names the automation and version, never its
command text. Inspect and repair those rows separately before retrying. Keep
old readers drained during the backfill: pre-0070 binaries cannot read the
envelopes, and 0070-only version inventories lack the 0071 canonical-digest
receipt. Backfilled rows cannot be downgraded to plaintext or rolled back
through 0071. Existing database backups still contain plaintext until they
expire or are replaced under the retention policy; retain their matching
master key and verify a restored copy before retiring backup generations.

For historical run logs, apply 0072 after draining old daemon, worker,
dashboard, and MCP readers. Its partial index keeps repeated backfill batches
from rescanning already-sealed history. After keyed startup and a consistent
database backup, run one bounded batch at a time:

```bash
reactor payload backfill-run-logs --db "$REACTOR_DB_URL" --root /var/lib/reactor --limit 32
```

Repeat until it reports `Encrypted 0 ... more=false`. The operation requires
the existing wrapped journal key and preserves exact log bytes, order, kind,
and timestamps. A malformed or oversized historical line aborts its batch
without partial conversion; inspect that row before retrying. Old readers
cannot read sealed lines, and pre-backfill backups still contain plaintext.
Retain the matching master key and verify a restore before retiring backup
generations.

## Monitoring

`/metrics` is Prometheus text format. Scrape with basic auth:

```yaml
scrape_configs:
  - job_name: reactor
    metrics_path: /metrics
    basic_auth:
      username: admin
      password: changeme
    static_configs:
      - targets: ["127.0.0.1:7777"]
```

Capacity gauges include `reactor_queue_depth`, `reactor_worker_count`, and
`reactor_worker_capacity`. The `reactor_capacity_probe_ok` gauge is `1` only
when both durable probes succeed; when it is `0`, the capacity gauges use `-1`
so dashboards do not turn a database outage into a false idle signal.
`reactor_queue_oldest_age_seconds` measures the oldest uncancelled queued row
(`0` for an empty queue); `reactor_queue_age_probe_ok=0` and an age of `-1`
mean that separate database probe failed. Disabled workflows can leave queued
rows behind, so a rising age needs a run-status check before it is read as
worker saturation. An index keeps the oldest-row probe bounded by queue order.
The daemon also exports `reactor_db_pool_{max_open,open,in_use,idle}_connections`
and cumulative `reactor_db_pool_wait_{total,seconds_total}` from its Go SQL
pool. Sustained connection waits with rising queue age indicate pressure at
the database boundary; more workers can increase that pressure. These are
per-process figures for `reactor serve`; dedicated `reactor worker` processes
do not expose an HTTP metrics endpoint yet, so this scrape does not measure
their connection pools. Each worker writes its own pool use and cumulative
connection waits in the minute-by-minute `worker: claim latency summary` log.

Counters: `reactor_runs_{started,succeeded,failed,dlq}_total`,
`_rotations_{run,error}_total`, `_mcp_calls_total`,
`_webhook_calls_total`. Gauges: `_uptime_seconds`, `_goroutines`,
`_memory_alloc_bytes`, `_memory_sys_bytes`, `_memory_gc_cycles_total`.

`/healthz` is unauthenticated (liveness probes) and returns
`{"ok":true,"version":"v0.1.0"}`.
It only proves that the HTTP listener is alive; it does not prove that the
database, scheduler, workers, or artifact store are ready. If the HTTP
listener exits unexpectedly, the daemon now cancels its other loops and exits
non-zero so a `Restart=on-failure` service manager can recover it.

`/readyz` is also unauthenticated and returns 200 only when the journal
database, workflow artifact state root, HTTP MCP handler, and serve runtime
components are available. The serve loop withdraws the `runtime` check when
the HTTP listener, scheduler, cron, or rotation component exits or shutdown
begins. It returns 503 with coarse per-dependency statuses while the daemon is
starting or recovering, so an orchestrator can keep traffic away until MCP
dispatch has a durable store behind it. When the process is started without a
command runner, it also returns 503 if this tenant has an enabled command plan
with an active schedule, webhook, or terminal chain. That guard is a
tenant-scoped existence check and does not inspect command text or trigger
payloads; ordinary command failures remain per-trigger when a runner is live.
It never includes raw database or filesystem errors in the public response.

### Terminal side-effect recovery

Terminal run status and the `terminal_effects` receipt are committed in one
database transaction. The serve leader retries receipts that were claimed but
not acknowledged after a crash, covering notification and workflow-complete
chain handoff. Notification and chain peers are all attempted; any failed
peer leaves the receipt retryable while the run itself remains terminal. This
is at-least-once handoff: a crash after a receiver accepted an event but
before acknowledgement can produce a duplicate. Downstream chain dispatches
use a deterministic source/trigger receipt so a retry does not duplicate peers
that already accepted their run.
Use `run_id` (or the chain payload's `source_run_id`) as the receiver's
deduplication key. The durable run status and step journal remain authoritative.

The dashboard's `/runs` page is the human equivalent; `/audit`
aggregates credential audits for incident review.

### AI post-mortem egress

AI post-mortems are off by default. `ANTHROPIC_API_KEY` alone may enable the
dashboard code-generation feature, but it does not authorize failed-run data
egress. Automatic generation and the MCP `reactor_record_postmortem` capability
are wired only when both of these are present:

```bash
REACTOR_AI_POSTMORTEM_ENABLED=true
ANTHROPIC_API_KEY=... # supply through the deployment secret manager
```

Before an Anthropic call, Reactor applies its PII/credential redactor and masks
sensitive values learned from run input and completed-step JSON in the stable
run/workflow/Step identifiers. It never sends `ErrorText`, trigger bodies, or
step output bodies. A failed step contributes only fixed fields such as
`error_present`, an allowlisted category, and a syntactically validated HTTP
status when explicitly labelled. This is defense-in-depth, not permission to
log customer data: keep signer names, emails, signing URLs, recipient objects,
bearer tokens, and customer payloads out of workflow error strings. Review the
configured Anthropic endpoint, region, retention, and processing agreement
before enabling the flag. To stop new egress, unset the opt-in and restart
every `serve`, `worker`, and MCP process. Apply the opt-in and Anthropic secret
consistently through the worker deployment; a distributed worker can own the
terminal DLQ transition and originate the post-mortem call.

## Scaling

Production scale-out uses `serve --mode distributed` for HTTP/enqueue and one
or more dedicated `reactor worker` processes against the same PostgreSQL
database. PostgreSQL is the queue; workers claim leased runs with
`FOR UPDATE SKIP LOCKED`. Multiple `serve` replicas may sit behind a load
balancer; PostgreSQL advisory-lock leader election limits scheduler, cron, and
rotation leadership to one replica. Do not run this topology on SQLite.

Workflow registration publishes a content-addressed SHA-256 artifact, records
its digest with the workflow version, and activates it without overwriting a
previous digest. Each run pins that version and digest; dispatch, worker
restart/resume, and DLQ redrive resolve the pinned immutable artifact rather
than the slug's newly active version. Every worker must nevertheless be able to
read the exact referenced digest. A shared read-only artifact mount or an
atomic, checksum-verified distribution to a read-only execution root on every
node are both valid estate choices. Registration/publishing may write its
staging area, but `serve` and worker execution must not mutate distributed
artifacts in place. Reactor does not currently garbage-collect version
artifacts: retain every digest referenced by a queued, running, suspended, or
DLQ run. Exercise
worker death, lease expiry, missing/corrupt local artifact, and version mismatch
in staging. A valid pin with unavailable local bytes must stay visibly blocked
and recoverable until the exact artifact is restored; an invalid persisted
version/digest identity must fail terminally. Neither case may execute mutable
or replacement bytes.

See [Scaling](/docs/scaling) for the current worker, leader-election,
multi-tenant, quota, and autoscaling contracts.

## Upgrade

Use a controlled, backed-up upgrade; do not infer rollback safety merely from a
`v0.x` tag:

```bash
# Stop the daemon (systemd: systemctl stop reactor)
apt install ./reactor_NEW_VERSION_amd64.deb
reactor migrate --db sqlite:///var/lib/reactor/reactor.db  # idempotent
# Restart
systemctl start reactor
```

The migration set is forward-only; downgrades require an independently reviewed
database restore or schema recovery plan.

The compiled-source selection upgrade changes dispatch admission for existing
source-proof version-2 artifacts. Before installing it, inventory enabled
workflows with `reactor_review_workflow` (or the dashboard) and check whether
their retained `.reactor-source-manifest.json` has `compiled_go_files`. An
enabled version-2 workflow lacking that pin will report
`compiled_files_unverified`; new dispatch is refused until it is rebuilt with
the new authoring path, reviewed, and re-enabled. Plan this as a quiesced,
backed-up cutover for those workflows, and verify preflight plus a real run
before reopening admission. There is no silent fallback to recursive source
scanning. Source-proof version-1 artifacts keep their explicit legacy dispatch
policy if already enabled; their visual flow stays unverified and activation of
a disabled legacy version still requires a rebuilt, verified artifact.

The release that adds durable `dlq_pending` repair checkpoints and exact DLQ
step identity requires a full old-worker drain. Do not mix workers from before
and after that wire/state transition:

1. Quiesce new trigger admission and disable autoscaling.
2. Gracefully drain and stop every old worker; verify that no old worker process
   or active old-generation lease remains.
3. Back up the database and matching key/artifact generation, then apply the
   migrations and upgrade `serve` plus the worker image.
4. Distribute the reviewed immutable artifacts to read-only execution roots.
5. Start only new-version workers, exercise worker restart, bounded retry, exact
   DLQ repair/redrive, and artifact-fence tests, then reopen admission.

If a worker cannot be proved drained, stop the cutover. An old worker does not
understand the new repair checkpoint contract and must never claim a run written
by the new release.

Migration `0031_workflow_artifact_pins` deliberately leaves legacy workflow
versions and runs without an artifact digest: the database cannot prove which
bytes a mutable pre-upgrade path executed. Treat that upgrade as a controlled
cutover, not a rolling migration:

1. Quiesce webhook, cron, chain, manual, MCP, and automation-trigger admission.
2. Inventory and drain, or explicitly disposition, every queued, running, and
   suspended run plus every DLQ item. Legacy runs cannot be safely resumed or
   redriven through the new artifact fence.
3. Apply migrations, then rebuild and re-register every enabled workflow so its
   current version has a content-addressed artifact digest.
4. Distribute and checksum-verify every referenced artifact on every serve and
   worker node before reopening admission.
5. Run pinned-version dispatch, worker-restart, resume, and DLQ-redrive smoke
   tests, then reopen triggers.

The `0031` Down migration is a schema rollback only: it deletes recorded run and
version pins. It is not a safe live runtime rollback and must not be used while
any run or DLQ item may need its pinned artifact.

## Disaster recovery

A lost master key is total credential data loss. There is NO recovery
mechanism: the BIP39 mnemonic earlier docs promised was never built, so
`<state>/master.key` is the only copy and backing it up out of band is
mandatory, not optional. The
workflows + run history survive (those are plaintext); only the vault
blob is encrypted-at-rest. Recovery options:

- Restore the matching SQLite archive, or the PostgreSQL + state/artifact
  recovery generation described above.
- Re-mint every credential via the rotation engine + grant chain;
  workflows resume with new credentials, no schema changes needed.

# Operations

## Install paths

| Path             | When                                                    |
| ---------------- | ------------------------------------------------------- |
| `brew install`   | macOS workstation development                            |
| `.deb` package   | Debian / Ubuntu servers (systemd-managed)               |
| `.rpm` package   | RHEL / Fedora servers (systemd-managed)                 |
| `docker run`     | Container-first deployments + ephemeral CI              |
| `docker-compose` | Development/single-node SQLite evaluation                |
| systemd unit     | Manual bare-metal install (built from source)           |

Every package + image is built from the same `v*` tag by
`.github/workflows/release.yml` and signed via the GitHub Actions
sigstore signer (when the release CI runs on a repo with the relevant
secrets).

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

The database and run history are not encrypted by `master.key`; encrypted vault
credentials are. Losing the key makes those credentials unrecoverable. For a
PostgreSQL deployment, back up PostgreSQL with a database-native consistent
mechanism and separately preserve the matching `master.key`, reviewed workflow
source/DAG, compiled artifacts and checksums, and deployment configuration. A
tar archive of `<root>` does not contain the PostgreSQL database and is not a
complete production backup. Restore a recovery generation into isolation and
prove vault decryption and workflow execution before accepting it.

The vault can re-encrypt on master-key rotation. Retain the previous key with
every backup generation that still needs it, and verify rotation/restore rather
than assuming a running rotation covered offline backups.

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

Counters: `reactor_runs_{started,succeeded,failed,dlq}_total`,
`_rotations_{run,error}_total`, `_mcp_calls_total`,
`_webhook_calls_total`. Gauges: `_uptime_seconds`, `_goroutines`,
`_memory_alloc_bytes`, `_memory_sys_bytes`, `_memory_gc_cycles_total`.

`/healthz` is unauthenticated (liveness probes) and returns
`{"ok":true,"version":"v0.1.0"}`.

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

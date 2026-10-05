# RFC: Command Automations + Supervised Execution

Status: Phase 1 (WebAuthn passkeys + TOTP + step-up sudo mode), the Phase 2
safe core, and the gated Phase 3 local Docker runner are implemented locally.
The runner is opt-in and requires a pinned Docker image, single-tenant
assertion, exact target allowlist, admin plus fresh step-up, and the HTTP MCP
command-execution scope. Credential delivery is now supported through the
same-tenant command grant ACL and a Docker CLI stdin pipe; SSH and
remote-host execution remain Phase 4 design work. This document is the
security contract the implementation must satisfy.

## Motivation

Operators accumulate shell-command automations (install a package on a host,
run a maintenance script, apply a fix) as loose scripts scattered across
servers with no versioning, no visibility, and no audit trail. The goal is to
bring those under Reactor's supervision: stored, versioned, visualized, and
observed, instead of running unattended and unrecorded on the hardware.

This is deliberately NOT "let workflows shell out." Reactor's codegen sandbox
bans `os/exec`, `syscall`, and friends in workflow Go on purpose (workflows are
AI-authored and potentially untrusted). That fence stays. Command execution is
added as a first-class, daemon-controlled, heavily gated capability, never as
arbitrary exec inside workflow code.

## Goals

1. Store command automations as first-class, git-versioned, visual entities.
2. Optionally execute them under supervision: durable, sandboxed, audited.
3. Do all of this without weakening the AI-authored-workflow sandbox.

## Non-goals

- Multi-tenant hosted command execution (v1). Self-host / single-tenant only.
- Replacing a CI system or a host-management agent. Reactor is the visual,
  versioned, audited store plus a sandboxed runner for the operator's own
  automations; heavier fleet execution can delegate to an external host agent.

## Design

### 1. The Command Automation model (the safe core, zero exec)

A command automation is a named, versioned entity:

- `name`, `description`, `tags`, target descriptor (host/context label)
- ordered `steps`, each with: the command (declarative), purpose, expected
  exit code, timeout, working dir, and credential references (vault key names,
  never inline secrets)
- durable `enabled` state, which starts false and can change only after the
  exact current version has been reviewed; enabled plans cannot be revised or
  deleted until they are disabled

It is stored, optionally git-versioned when the configured workflow directory is
inside an operator-managed repository, and rendered in the DAG / flow view. Git
history is not created automatically and is not the sole audit record. This half adds no execution and
no new attack surface: it is data plus rendering. It already delivers the core
value (visibility, ownership, versioning, diffs, audit) with zero risk.

The MCP create mutation accepts an optional tenant-scoped `idempotency_key`.
The journal binds that key to the actor, metadata, and normalized version-1
definition in the same transaction as the plan, so a lost HTTP response can be
retried without creating a second plan and key reuse with changed input is
rejected. A no-key create retains the tenant-unique name conflict and a
same-actor exact version-1 replay convenience for legacy callers.

### 2. Supervised execution (gated)

A first-class command step type that the DAEMON runs, never workflow `os/exec`:

- Executes in a throwaway, locked-down container (non-root, no host filesystem
  mounts by default, CPU/memory limits, restricted network).
- stdout / stderr / exit code stream to the durable run journal, so every run
  is observable and replayable.
- Timeout plus a stuck-command reaper (claim-keyed, paired with a result
  idempotency guard so a long-running command is not false-reaped or run twice).
- An SSH command variant connects to a target host with a key resolved from the
  vault at run time (grant-ACL gated), runs the command, and captures output.
- Two backends: a local sandbox (container on the daemon host) or delegation to
  an external host-management agent that already owns the host-command path.

`reactor_set_command_automation_state` is the explicit review-to-runtime
transition. Enabling requires an administrator's fresh step-up and the exact
current version; disabling is an emergency stop. `reactor_preflight_command_automation`
evaluates each gate independently for one exact immutable version and returns a
bounded point-in-time receipt. It
also returns deterministic, secret-free `gate_digest` and `receipt_id` values
bound to the tenant, automation, version, normalized definition digest, and
gate result. `reactor_run_command_automation` accepts that exact binding only
after the HTTP command-execution scope is enabled; the daemon re-evaluates the
definition, authenticated actor, step-up, target, sandbox, ACL, output, and
journal gates immediately before creating a durable queued run. The HTTP
handler returns that receipt without starting a process. A fixed worker pool
claims the row asynchronously, and a tenant-scoped recovery poll resumes rows
left queued across restart or in-memory backpressure. A missing capability provider
or runner remains closed by default. Migrations 0041–0044 and the journal methods
retain the exact definition digest, gate receipt, worker lease, ordered step
attempts, bounded redacted output, and tenant-scoped retry lineage. Retry
lineage stores only the source run id; command values, output, and credentials
are never copied. The Docker adapter uses no mounts or
network. Credential references are resolved only after the run step is leased,
must have an explicit command grant, and are passed by hashed environment names
through Docker's line-oriented env-file parser over stdin, with no plaintext
host env-file; exact values are scrubbed from stdout, stderr, and errors before
journal persistence. Transformed or partial values may evade that scrubber. Newline-bearing
values are rejected by this line-oriented delivery path. If a worker fails, the
terminal transaction closes every pending/running step and attempt. An explicit
`reactor_cancel_command_run` first fences the durable claim and then closes the
run; a daemon shutdown or lost request context is not an operator cancellation,
so the worker leaves its live claim recoverable and the lease reaper requeues it
after expiry.

Streaming-capable sandboxes append bounded stdout and stderr to the live step
and claimed attempt projections while a process is still running. Every append
uses the same run lease, worker, step, and attempt fence as terminal writes, and
the journal keeps cumulative byte counts and truncation flags. The stream is a
current-state projection rather than an immutable chunk archive; the final
step-result write remains authoritative after the sandbox exits. Exact
credential values are redacted before an append, including values split across
pipe writes, with the generic journal redactor as a second boundary.

Run admission is idempotent at the durable journal boundary. The runner derives
a stable run id when the MCP caller does not supply one, and an explicit run id
is bound to the complete receipt and immutable version. A matching retry returns
the existing run without reclaiming or replaying it; a mismatch is rejected.
Admission also requires that the plan is still enabled and that the requested
version is the current version, so disabling or revising a plan cannot leave an
old receipt executable.

The daemon's preflight provider projects an authenticated admin role and a
fresh dashboard-session step-up window. A dedicated HTTP MCP bearer does not
carry session assurance and cannot satisfy the step-up gate by itself. The
runner, sandbox, output, audit, feature, and single-tenant gates are wired only
when their explicit flags and pinned backend are present. Credential-bearing
plans additionally require the configured vault/OAuth resolver, tenant check,
and command-specific grant ACL; missing or unsupported resolvers keep the
credential-support gate closed.
Salesforce OAuth connections and recognized Salesforce endpoint aliases are
broker-only: command plans cannot materialize their access tokens into a
container environment. The preflight and the materializer both reject those
references, and the OAuth store rechecks the policy when resolving a raw
token. Salesforce command operations need a separately reviewed host-brokered
adapter; a workflow's GET-only connector cannot be used to enable command
writes. Other OAuth providers retain their legacy raw-token path for now.

The HTTP MCP surface also exposes `reactor_list_command_runs` and
`reactor_get_command_run` as read-only inspection tools. They are tenant-bound,
page-bounded projections of the durable run and step journal: immutable
definition and admission digests, ordered statuses, exit codes, and bounded
untrusted output are available for an AI or operator to diagnose a command
runner. Claim tokens, command text, and credential values remain outside the
projection. These tools cannot launch or retry a run; execution and
cancellation are separate mutations with their own scope. The
`reactor_cancel_command_run` mutation accepts only a bounded tenant-scoped run
identity and reason, fences the durable claim before interrupting a local
worker, and closes unfinished step projections in the same transaction. A
worker in another daemon generation is denied by the cleared claim token and
lease checks. `reactor_retry_command_run` is a separate explicit recovery
mutation: it accepts only a failed or cancelled source receipt, requires a
fresh preflight binding, verifies that the source plan is still enabled at the
same immutable version, and allocates a distinct run identity before passing
the request through normal runner admission. A caller-supplied identity is an
idempotency key: an exact repeated request returns its existing durable retry,
while a different receipt or source is rejected. It preserves the source run
id as audit metadata without copying command values, outputs, or credentials.

### 2a. Unattended cron schedules

Unattended command execution uses the dedicated `command_automation_schedules`
table; workflow `triggers` are never retargeted to a command plan. A schedule
stores only the tenant, exact current plan version, normalized-definition
digest, preflight receipt binding, actor identity, standard five-field cron
expression, IANA timezone, and a revision-fenced state. Creation always starts
disabled. Activation requires the plan to remain enabled and current plus a
fresh admin/step-up preflight with current tenant, grant, resolver, sandbox,
target, output, and audit facts. Schedule mutation requires both the trigger
and command-execution MCP scopes.

The command schedule driver runs only on the existing single leader, reloads
active rows, and admits each fire through `Runner.AdmitScheduled`. The final
command-run transaction locks and rechecks the schedule row, so a disable or
delete racing a callback prevents a new run. Event identity is deterministic
for schedule and minute slot; it is retained in bounded run admission metadata
and survives queue recovery. A fixed admission semaphore protects the daemon
when many schedules fire together, while the existing bounded command queue
limits process concurrency. Schedule views expose cadence, state, revision,
and last-fire metadata, but never command text, credentials, idempotency keys,
or raw runtime errors.

### 2b. Unattended HTTP webhook ingress

Command-plan webhooks use a dedicated `command_automation_webhook_triggers`
table and the `/command-webhook/{token}` namespace. They are never represented
as workflow `triggers`, so a workflow bearer cannot acquire command execution
authority through a shared lookup. A binding stores only the tenant, exact
immutable plan version, definition digest, preflight receipt, gate digest,
actor, provider, and a vault reference to a dedicated `reactor-webhook`
shared-secret credential. The token is generated with a `cmdwhk_` prefix and
is returned only by the create/replay receipt; list and inspect projections
omit both the token and secret reference.

MCP creation is idempotent and always starts disabled. State changes use an
optimistic revision fence; enabling requires the bound plan to remain enabled
at its current version, fresh administrator plus step-up authorization, and
all current target, sandbox, credential, output, audit, and runner gates. The
MCP server also requires a daemon-owned ingress-runtime readiness callback
before activation, so authoring a row cannot make an endpoint appear live
before its HTTP verifier and command admission adapter are mounted. The
receiver must verify the provider's HMAC contract before claiming a delivery,
reuse the existing lease-based webhook deduplication boundary, and admit a run
through a trigger-specific runner path that rechecks the exact receipt and
tenant binding. Request bodies are bounded transient input; neither body nor
secret is copied into the command plan, MCP result, or durable command-run
receipt. For `generic` and `github` providers, the command receiver ignores
the unsigned delivery header and uses the authenticated body hash as the
delivery identity, so changing that header cannot mint a second run. Their
body-only signatures still lack timestamp freshness; timestamped
`automation-v1`, `hash-v1`, or Stripe bindings are preferred for commands that
must reject a captured body outside the normal webhook-dedup retention window.

### 2c. Unattended workflow-complete command chains

Command plans can also bind to the terminal result of one tenant-owned
workflow through the dedicated `command_automation_chain_triggers` table. The
source workflow identity is checked when the binding is created and again by
the terminal hook; a source run from another tenant, a missing source, or a
legacy row without a provable tenant is skipped or rejected before command
admission. Chain rows start disabled and require the same exact immutable
version, definition digest, preflight receipt, plan enablement, runner, and
fresh administrator/step-up review as other unattended triggers. They require
both the trigger and command-execution MCP scopes.

The terminal hook accepts only `succeeded`, `failed`, and `failed_dlq` outcomes
and derives a deterministic event id from the trigger, source run, and status.
It admits through `Runner.AdmitChain`, creates the durable queued command run,
and hands it to the bounded command queue. A queue-full result remains a
recoverable durable row; the trigger is acknowledged only after admission, so
terminal-effect retries cannot create a second run. Disabling or changing the
exact binding fences a racing callback in the final journal transaction. No
source workflow payload, error text, command text, credentials, or output is
copied into the command run.

### 3. The gates (defense in depth, each layer independent)

```
off by default (feature flag)
  -> single-tenant only (hard-refused in any hosted / multi-tenant mode)
    -> admin-only (never members / viewers)
      -> step-up auth (fresh passkey assertion) to enable / run / reveal
        -> explicit plan enablement after review
          -> daemon-sandboxed execution (container, not workflow os/exec)
            -> credentials from the grant-ACL vault, never inline
              -> every run + command + output + actor in the durable audit journal
```

1. Off by default: `REACTOR_COMMAND_RUNNER_ENABLED=1` plus the separate HTTP
   `REACTOR_MCP_ALLOW_COMMAND_EXECUTION=1` scope
   registers the step type at all. Absent, the capability does not exist, so it
   is not a standing liability for anyone who has not opted in.
2. Single-tenant only: hard-refuse when a hosted / multi-tenant mode flag is
   set. Multi-tenant command execution on shared infrastructure is a
   cross-tenant / host compromise vector and is out of scope until per-tenant
   isolated runners exist (ephemeral VM/container per job).
3. Admin-only: only admins may author, enable, or run command steps. Members
   and viewers never can. Ungated command routes reachable by non-admins are
   the single worst failure mode for this class of feature.
4. Step-up auth: a fresh WebAuthn passkey assertion (or TOTP fallback) is
   required to enable a plan, run a command, or reveal / rotate a secret.
   A valid session cookie alone never authorizes these.
5. Sandboxed: container isolation, non-root, no host mounts by default,
   resource and network limits.
6. Vaulted credentials: SSH keys and tokens live in the vault, gated by the
   per-workflow grant ACL (strict-deny default), never inline in the automation
   definition. Plaintext is materialized only inside the sandboxed run.
7. Audited: every run, its command, output, exit code, and the acting admin are
   recorded in the durable journal.
8. AI-builder fence stays: the codegen import allowlist still bans `os/exec` in
   workflow Go. A command step is DECLARATIVE data the AI (or an operator) emits;
   the daemon runs it through the gated path. The AI cannot smuggle raw exec,
   and any command step it produces is still subject to every gate above.

### 4. WebAuthn / step-up auth (the foundation)

Reactor's MFA foundation is in place. It provides:

- WebAuthn passkeys (platform authenticators / hardware keys) for phishing-
  resistant MFA.
- TOTP plus one-time recovery codes as the fallback MFA path.
- A step-up "sudo mode": a short-lived elevated-auth window minted by a fresh
  passkey / TOTP assertion, required for the dangerous actions (enable command
  steps, run a command, reveal / rotate a secret). This closes Reactor's MFA
  gap generally, not just for this feature.

## Threat model

| Threat | Mitigation |
|---|---|
| Non-admin triggers a command -> RCE | admin-only + step-up; members cannot reach it |
| Tenant attacks shared host in multi-tenant hosting | hard-disabled in hosted mode; single-tenant self-host only |
| AI-authored workflow smuggles `os/exec` | import allowlist bans it; command step is declarative, daemon-run, gated |
| Uploaded workflow tarball includes a command step | same gates; runs only if enabled + admin + step-up |
| Stolen session cookie runs a command | step-up passkey required; cookie alone is insufficient |
| Command exfiltrates a secret | vault grant ACL (strict-deny); creds only in the sandboxed run; output redaction |
| Runaway / destructive command | container sandbox (no host mount), resource limits, timeout, reaper, audit |
| Secret hardcoded in the automation definition | credentials are vault references, never inline; secret scanning on the repo |

## Phasing

- Phase 1: WebAuthn passkeys + TOTP + step-up sudo mode (auth foundation; also
  fixes the general MFA gap). DONE. Enroll factors at `/security`; a user with a
  factor is challenged at login and must step up ("sudo") for sensitive changes.
  TOTP secrets are AES-256-GCM encrypted (key derived from the daemon master key
  via HKDF); passkeys need `REACTOR_WEBAUTHN_RP_ID` + `REACTOR_WEBAUTHN_RP_ORIGIN`
  (or `REACTOR_DASHBOARD_URL`).
- Phase 2: Command Automation store + visual DAG + git versioning (safe, no exec).
  The current MCP surface implements the bounded store, immutable revisions,
  and flow projection. Git commit integration remains a separate operator-owned
  concern; this surface does not create commits automatically, execute steps,
  or make a plan eligible for dispatch. Read paths normalize stored definitions
  again before rendering a flow, review, diff, resource, or graph edge, so a
  malformed legacy/imported row fails closed instead of becoming a misleading
  visual or readiness receipt.
- Phase 3: Sandboxed command runner (container) behind the flag + all gates.
  The Docker backend, durable leases, reaper, explicit plan enablement, HTTP
  MCP mutation, grant-checked vault/OAuth materialization, stdin credential delivery,
  exact output scrubbing, and the receipt-bound disabled-by-default cron,
  webhook, and workflow-complete trigger paths are implemented. Each trigger
  has a separate durable table, tenant fence, deterministic provenance, and
  final admission check; none retargets the workflow trigger table.
- Phase 4: SSH step + external-host-agent delegation option.

## Open questions

- Execution backend for v1: daemon-local container vs. external-host-agent
  delegation vs. both.
- Sandbox technology: a locked `docker run --rm` profile initially; a stronger
  isolation layer (microVM) if untrusted execution is ever hosted.

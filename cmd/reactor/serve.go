package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bright-interaction/reactor/internal/auth"
	"github.com/bright-interaction/reactor/internal/autoscale"
	"github.com/bright-interaction/reactor/internal/codegen"
	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/dispatcher"
	"github.com/bright-interaction/reactor/internal/flarereport"
	"github.com/bright-interaction/reactor/internal/graph"

	"github.com/bright-interaction/reactor/internal/catalog"
	"github.com/bright-interaction/reactor/internal/commandautomations"
	"github.com/bright-interaction/reactor/internal/commandrunner"
	"github.com/bright-interaction/reactor/internal/knowledge"
	"github.com/bright-interaction/reactor/internal/mcp"
	"github.com/bright-interaction/reactor/internal/migrate"
	"github.com/bright-interaction/reactor/internal/notifier"
	"github.com/bright-interaction/reactor/internal/oauth"
	"github.com/bright-interaction/reactor/internal/postmortem"
	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/rotators"
	"github.com/bright-interaction/reactor/internal/runlogs"
	"github.com/bright-interaction/reactor/internal/runtime/cancelreg"
	"github.com/bright-interaction/reactor/internal/runtime/commandwebhook"
	"github.com/bright-interaction/reactor/internal/runtime/cron"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
	"github.com/bright-interaction/reactor/internal/runtime/supervisor"
	"github.com/bright-interaction/reactor/internal/runtime/webhook"
	"github.com/bright-interaction/reactor/internal/server"
	"github.com/bright-interaction/reactor/internal/vault"
	"github.com/bright-interaction/reactor/internal/workflowproof"
)

// cmdServe is the daemon entrypoint. Boots every component the runtime
// needs and blocks until SIGINT/SIGTERM. Components started:
//
//   - HTTP server (status pages + webhook + signal routes)
//   - Cron driver (active cron-kind triggers)
//   - Scheduler (Sleep/AwaitSignal resume + signal expiry)
//   - Rotation runner (auto-rotates credentials on schedule)
//
// The supervisor itself is spawned per-run by the dispatcher; nothing
// runs at boot beyond what's wired here.
func cmdServe(ctx context.Context, log *slog.Logger, args []string) error {
	cfg, err := parseServeFlags(args)
	if err != nil {
		return err
	}
	// Error reporting to Flare (no-op unless FLARE_DSN is set; the DSN is
	// injected by the Hephaestus flare-provision deploy step).
	flarereport.InitFlare("reactor", Version)
	deps, err := openServeDeps(ctx, log, cfg)
	if err != nil {
		return err
	}
	defer deps.db.Close()
	srv := buildHTTPServer(log, cfg, deps)
	return runServeLoop(ctx, log, cfg, deps, srv)
}

// serveConfig holds every parsed flag value. parseServeFlags is the
// only function that touches the flag.FlagSet, env vars, and master
// key resolution; everything else reads from this struct.
type serveConfig struct {
	dbURL             string
	addr              string
	tlsCert           string
	tlsKey            string
	root              string
	masterKey         []byte
	previousMasterKey []byte
	tickInterval      time.Duration
	rotationInterval  time.Duration
	cronReload        time.Duration
	drainTimeout      time.Duration
	aclPermissive     bool
	cgroupRoot        string
	requireCgroup     bool
	insecureNoAuth    bool
	mcpToken          string
	mcpTenant         string
	mcpTrustedProxy   bool
	trustedProxies    server.TrustedProxyPolicy
	// oauthRedirectURI is a fixed, operator-configured callback used by the
	// MCP consent tool. It is deliberately separate from request-derived Host
	// values so an MCP caller cannot choose the provider callback destination.
	oauthRedirectURI string

	// MCP write capabilities are deliberately opt-in for the long-running
	// HTTP daemon. The route is admin-gated, but an explicit capability
	// switch keeps a read-only deployment read-only even when the dispatcher
	// and vault are available in-process.
	mcpAuthoring           bool
	mcpTriggers            bool
	mcpNotifications       bool
	mcpDispatch            bool
	mcpSecrets             bool
	mcpKnowledge           bool
	mcpDiagnostics         bool
	mcpDataExport          bool
	mcpDataLifecycle       bool
	mcpMailReconciliation  bool
	mcpArtifactPublication bool
	mcpCommandExecution    bool
	commandRunnerEnabled   bool
	commandSingleTenant    bool
	commandDockerBinary    string
	commandDockerImage     string
	commandTargets         []string
	commandRunnerWorkers   int
	commandRunnerQueue     int
	commandRunnerPoll      time.Duration

	// mode is "local" (single-node, execute in-process) or "distributed"
	// (enqueue runs for `reactor worker` processes to claim). Distributed
	// mode requires Postgres.
	mode string
	// workerArtifactRoot overrides the local state root for immutable workflow
	// bytes on workers with a separately mounted, read-only artifact tree.
	workerArtifactRoot string
	// queueArtifactRoot is the serving daemon's read-only view of the worker
	// artifact tree. It fences queued admissions without preventing local dry
	// runs while an authored artifact is still being published there.
	queueArtifactRoot string

	// autoscale enables the worker autoscaler on the leader (distributed
	// mode only). Off by default -- a self-replicating system is opt-in.
	autoscale       bool
	autoscaleConfig autoscale.Config
}

// distributed reports whether the daemon runs in queue mode.
func (c *serveConfig) distributed() bool { return c.mode == "distributed" }

func (c *serveConfig) executionArtifactRoot() string {
	if c.workerArtifactRoot != "" {
		return c.workerArtifactRoot
	}
	return c.root
}

// parseServeFlags fills a serveConfig from CLI args + env vars,
// resolves the master key, and validates the bare minimum (db URL +
// root). Migrations are deliberately not run here so a flag-parse
// failure doesn't half-migrate the schema.
func parseServeFlags(args []string) (*serveConfig, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dbURL := fs.String("db", envFirst("REACTOR_DB_URL", "ARACHNE_DB_URL"), "database URL (sqlite://path or postgres://...)")
	// Keep the default local, matching the HTTP MCP install/check defaults and
	// the Mesh serving-command contract. A non-loopback listener is an explicit
	// deployment decision and must also satisfy the TLS or trusted-proxy gate
	// below; leaving this as :7777 would make the ordinary quickstart fail at
	// startup before it can serve the dashboard or MCP endpoint.
	addr := fs.String("addr", "127.0.0.1:7777", "HTTP listen address (default: loopback; use an explicit non-loopback address with TLS or --mcp-trusted-proxy)")
	tlsCert := fs.String("tls-cert", envFirst("REACTOR_TLS_CERT", "ARACHNE_TLS_CERT"), "path to TLS cert (PEM); empty = plain HTTP")
	tlsKey := fs.String("tls-key", envFirst("REACTOR_TLS_KEY", "ARACHNE_TLS_KEY"), "path to TLS key (PEM); both --tls-cert and --tls-key must be set together")
	root := fs.String("root", defaultRoot(), "Reactor state directory (workflows/ + master.key)")
	masterKeyFile := fs.String("master-key-file", "", "path to a 64-hex-char master key (default <root>/master.key)")
	masterKeyHex := fs.String("master-key", envFirst("REACTOR_MASTER_KEY", "ARACHNE_MASTER_KEY"), "32-byte hex master key (overrides --master-key-file)")
	tickInterval := fs.Duration("scheduler-tick", 5*time.Second, "scheduler poll interval")
	rotationInterval := fs.Duration("rotation-tick", time.Hour, "rotation runner tick interval")
	cronReload := fs.Duration("cron-reload", 30*time.Second, "interval at which the cron driver re-syncs the triggers table; 0 disables live-reload")
	drainTimeout := fs.Duration("drain-timeout", time.Duration(envIntFirst("REACTOR_DRAIN_TIMEOUT", "ARACHNE_DRAIN_TIMEOUT", 30))*time.Second, "max time to wait for in-flight workflows to finish on SIGINT before force-cancelling")
	aclPermissive := fs.Bool("vault-acl-permissive", os.Getenv("REACTOR_VAULT_ACL_PERMISSIVE") == "1", "when set, an empty workflow_secret_grants table allows same-tenant fetches (legacy v0 behaviour). Run identity and tenant checks still apply. Default (strict) denies on empty so an operator must explicitly grant per workflow.")
	cgroupRoot := fs.String("cgroup-root", os.Getenv("REACTOR_CGROUP_ROOT"), "when set (typical: /sys/fs/cgroup), each workflow subprocess lands in a per-run cgroup v2 with memory.max + pids.max. Falls back to prlimit-only when the path isn't a cgroup v2 mount or the daemon lacks write perms.")
	requireCgroup := fs.Bool("require-workflow-cgroup", os.Getenv("REACTOR_REQUIRE_WORKFLOW_CGROUP") == "1", "fail a workflow run unless per-run cgroup v2 isolation and cgroup.kill descendant cleanup are available")
	insecureNoAuth := fs.Bool("insecure-no-auth", os.Getenv("REACTOR_INSECURE_NO_AUTH") == "1", "EXPLICIT opt-in to run the dashboard with no authentication when REACTOR_BASIC_AUTH_USER / REACTOR_BASIC_AUTH_PASSWORD_SHA256 are unset. Default (false) fails closed with HTTP 503 until creds are configured.")
	mcpToken := fs.String("mcp-token", envFirst("REACTOR_MCP_TOKEN", "ARACHNE_MCP_TOKEN"), "dedicated bearer token accepted by the HTTP MCP endpoint; API tokens remain supported")
	mcpTenant := fs.String("mcp-tenant", envFirstOr(journal.DefaultTenant, "REACTOR_MCP_TENANT", "ARACHNE_MCP_TENANT"), "tenant bound to the dedicated HTTP MCP bearer token")
	mcpTrustedProxy := fs.Bool("mcp-trusted-proxy", os.Getenv("REACTOR_MCP_TRUSTED_PROXY") == "1", "allow plain HTTP MCP on a non-loopback listener only when an authenticated TLS-terminating proxy is in front of this process")
	trustedProxyCIDRs := fs.String("trusted-proxy-cidrs", os.Getenv("REACTOR_TRUSTED_PROXY_CIDRS"), "comma-separated exact proxy IPs/CIDRs allowed to supply X-Forwarded-* headers (loopback trusted by default)")
	mcpAuthoring := fs.Bool("mcp-allow-authoring", os.Getenv("REACTOR_MCP_ALLOW_AUTHORING") == "1", "enable authenticated HTTP MCP workflow validation and creation tools")
	mcpTriggers := fs.Bool("mcp-allow-triggers", os.Getenv("REACTOR_MCP_ALLOW_TRIGGERS") == "1", "enable authenticated HTTP MCP trigger management tools")
	mcpNotifications := fs.Bool("mcp-allow-notifications", os.Getenv("REACTOR_MCP_ALLOW_NOTIFICATIONS") == "1", "enable authenticated HTTP MCP notification routing tools")
	mcpDispatch := fs.Bool("mcp-allow-dispatch", os.Getenv("REACTOR_MCP_ALLOW_DISPATCH") == "1", "enable authenticated HTTP MCP workflow dispatch and cancellation tools")
	mcpSecrets := fs.Bool("mcp-allow-secrets", os.Getenv("REACTOR_MCP_ALLOW_SECRETS") == "1", "enable authenticated HTTP MCP vault grant and revoke tools")
	mcpKnowledge := fs.Bool("mcp-allow-knowledge", os.Getenv("REACTOR_MCP_ALLOW_KNOWLEDGE") == "1", "enable authenticated HTTP MCP knowledge write tools")
	mcpDiagnostics := fs.Bool("mcp-allow-diagnostics", os.Getenv("REACTOR_MCP_ALLOW_DIAGNOSTICS") == "1", "enable authenticated HTTP MCP diagnostic egress tools")
	mcpDataExport := fs.Bool("mcp-allow-data-export", os.Getenv("REACTOR_MCP_ALLOW_DATA_EXPORT") == "1", "enable authenticated HTTP MCP exact run-input reads and bulk tenant export")
	mcpDataLifecycle := fs.Bool("mcp-allow-data-lifecycle", os.Getenv("REACTOR_MCP_ALLOW_DATA_LIFECYCLE") == "1", "enable authenticated HTTP MCP tenant run-history erasure after explicit confirmation")
	mcpMailReconciliation := fs.Bool("mcp-allow-mail-reconciliation", os.Getenv("REACTOR_MCP_ALLOW_MAIL_RECONCILIATION") == "1", "enable admin HTTP MCP recording of an operator finding for uncertain connected-mail sends")
	mcpArtifactPublication := fs.Bool("mcp-allow-artifact-publication", os.Getenv("REACTOR_MCP_ALLOW_ARTIFACT_PUBLICATION") == "1", "enable authenticated HTTP MCP requests to publish reviewed workflow artifacts to distributed worker storage")
	mcpCommandExecution := fs.Bool("mcp-allow-command-execution", os.Getenv("REACTOR_MCP_ALLOW_COMMAND_EXECUTION") == "1", "enable authenticated HTTP MCP command-plan execution through the separately configured sandbox runner")
	commandRunnerEnabled := fs.Bool("command-runner-enabled", os.Getenv("REACTOR_COMMAND_RUNNER_ENABLED") == "1", "enable the explicitly configured command-plan runner; requires a pinned Docker image and single-tenant opt-in")
	commandSingleTenant := fs.Bool("command-single-tenant", os.Getenv("REACTOR_COMMAND_SINGLE_TENANT") == "1", "allow command execution only when the operator explicitly asserts this daemon is single-tenant")
	commandDockerBinary := fs.String("command-docker-binary", envFirstOr("/usr/bin/docker", "REACTOR_COMMAND_DOCKER_BINARY"), "absolute Docker binary used by the command sandbox")
	commandDockerImage := fs.String("command-docker-image", envFirst("REACTOR_COMMAND_DOCKER_IMAGE"), "pinned Docker image digest used by the command sandbox")
	commandTargets := fs.String("command-targets", envFirst("REACTOR_COMMAND_TARGETS"), "comma-separated exact command target descriptors allowed by the sandbox")
	commandRunnerWorkers := fs.Int("command-runner-workers", envIntFirst("REACTOR_COMMAND_RUNNER_WORKERS", "", 2), "fixed command-runner worker count (1..64)")
	commandRunnerQueue := fs.Int("command-runner-queue", envIntFirst("REACTOR_COMMAND_RUNNER_QUEUE", "", 16), "bounded admitted command-runner queue capacity")
	commandRunnerPoll := fs.Duration("command-runner-poll", envDurationFirst("REACTOR_COMMAND_RUNNER_POLL", "", time.Second), "durable queued-command recovery poll interval")
	mode := fs.String("mode", envFirstOr("local", "REACTOR_MODE"), "execution mode: 'local' (single-node, run workflows in-process) or 'distributed' (enqueue runs for `reactor worker` processes; requires Postgres)")
	workerArtifactRoot := fs.String("worker-artifact-root", os.Getenv("REACTOR_WORKER_ARTIFACT_ROOT"), "distributed serve: read-only view of the exact worker artifact tree containing workflows/; required for worker-storage admission proof")
	autoscaleEnabled := fs.Bool("autoscale", os.Getenv("REACTOR_AUTOSCALE") == "1", "distributed mode only: the leader spawns/stops `reactor worker` processes to track queue depth (bounded by REACTOR_AUTOSCALE_MAX, default 4). Off by default.")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return nil, err
	}
	// A partially configured TLS pair is almost certainly an operator typo.
	// RunWithTLS treats an empty pair as an intentional plain-HTTP listener,
	// so fail closed here instead of silently downgrading a deployment when
	// only one of the certificate or key paths is present.
	if (strings.TrimSpace(*tlsCert) == "") != (strings.TrimSpace(*tlsKey) == "") {
		return nil, errors.New("serve: --tls-cert and --tls-key must be provided together")
	}
	if *dbURL == "" {
		return nil, errors.New("missing --db (or REACTOR_DB_URL env var)")
	}
	if *root == "" {
		return nil, errors.New("missing --root (and HOME unset)")
	}
	if err := validateWorkflowCgroupConfig(*cgroupRoot, *requireCgroup); err != nil {
		return nil, err
	}
	if strings.TrimSpace(*mcpTenant) == "" {
		return nil, errors.New("missing --mcp-tenant (or REACTOR_MCP_TENANT)")
	}
	oauthRedirectURI, err := mcpOAuthRedirectURI(envFirst("REACTOR_DASHBOARD_URL", "ARACHNE_DASHBOARD_URL"))
	if err != nil {
		return nil, err
	}
	dashboardAuthConfigured := strings.TrimSpace(envFirst("REACTOR_BASIC_AUTH_USER", "ARACHNE_BASIC_AUTH_USER")) != "" &&
		strings.TrimSpace(envFirst("REACTOR_BASIC_AUTH_PASSWORD_SHA256", "ARACHNE_BASIC_AUTH_PASSWORD_SHA256")) != ""
	if err := validateMCPExposure(*addr, *mcpToken, *insecureNoAuth, dashboardAuthConfigured, strings.TrimSpace(*tlsCert) != "", *mcpTrustedProxy); err != nil {
		return nil, err
	}
	trustedProxies, err := server.ParseTrustedProxyCIDRs(*trustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	if *mode != "local" && *mode != "distributed" {
		return nil, fmt.Errorf("invalid --mode %q (want local or distributed)", *mode)
	}
	if *mode == "distributed" && !isPostgresURL(*dbURL) {
		return nil, errors.New("--mode distributed requires a postgres:// database (SQLite can't back multiple worker processes)")
	}
	if err := validateAutoscaleCommandConfig(*mode == "distributed", *autoscaleEnabled, *root); err != nil {
		return nil, err
	}
	var autoscaleConfig autoscale.Config
	if *mode == "distributed" && *autoscaleEnabled {
		autoscaleConfig, err = parseAutoscaleConfig()
		if err != nil {
			return nil, err
		}
	}
	queueArtifactRoot := ""
	if *mode == "distributed" && *workerArtifactRoot != "" {
		if !validAbsoluteMountPath(*workerArtifactRoot) {
			return nil, errors.New("--worker-artifact-root (or REACTOR_WORKER_ARTIFACT_ROOT) must be a clean absolute path")
		}
		queueArtifactRoot = *workerArtifactRoot
	}
	if *mode == "distributed" && *autoscaleEnabled {
		substrate := strings.ToLower(strings.TrimSpace(envFirstOr("process", "REACTOR_AUTOSCALE_SPAWNER")))
		if substrate == "kubernetes" || substrate == "k8s" {
			var kubernetesRoot string
			_, kubernetesRoot, err = kubernetesArtifactMountConfig(*root)
			if err != nil {
				return nil, err
			}
			if queueArtifactRoot != kubernetesRoot {
				return nil, errors.New("--worker-artifact-root must match REACTOR_WORKER_ARTIFACT_ROOT for the Kubernetes worker PVC")
			}
		}
	}
	if *commandRunnerEnabled {
		if !*commandSingleTenant {
			return nil, errors.New("command runner requires --command-single-tenant (or REACTOR_COMMAND_SINGLE_TENANT=1)")
		}
		if *mode != "local" {
			return nil, errors.New("command runner requires --mode local until isolated per-tenant workers are supported")
		}
		if strings.TrimSpace(*commandDockerImage) == "" {
			return nil, errors.New("command runner requires --command-docker-image (or REACTOR_COMMAND_DOCKER_IMAGE) pinned by digest")
		}
		if *commandRunnerWorkers < 1 || *commandRunnerWorkers > 64 {
			return nil, errors.New("command runner requires --command-runner-workers between 1 and 64")
		}
		if *commandRunnerQueue < *commandRunnerWorkers || *commandRunnerQueue > 4096 {
			return nil, fmt.Errorf("command runner requires --command-runner-queue between %d and 4096", *commandRunnerWorkers)
		}
		if *commandRunnerPoll <= 0 || *commandRunnerPoll > time.Hour {
			return nil, errors.New("command runner requires --command-runner-poll between 1ns and 1h")
		}
	}
	masterHex, err := loadMasterKey(*masterKeyHex, *masterKeyFile, *root)
	if err != nil {
		return nil, err
	}
	masterKey, err := decodeMasterKey(masterHex)
	if err != nil {
		return nil, err
	}
	// Optional previous master key for a rotation window: set both
	// REACTOR_MASTER_KEY (new) and REACTOR_MASTER_KEY_PREVIOUS (old) and the
	// vault lazily re-encrypts each secret under the new key on read.
	var previousMasterKey []byte
	if prevHex := envFirst("REACTOR_MASTER_KEY_PREVIOUS", "ARACHNE_MASTER_KEY_PREVIOUS"); prevHex != "" {
		previousMasterKey, err = decodeMasterKey(prevHex)
		if err != nil {
			return nil, fmt.Errorf("REACTOR_MASTER_KEY_PREVIOUS: %w", err)
		}
	}
	return &serveConfig{
		dbURL:                  *dbURL,
		addr:                   *addr,
		tlsCert:                *tlsCert,
		tlsKey:                 *tlsKey,
		root:                   *root,
		masterKey:              masterKey,
		previousMasterKey:      previousMasterKey,
		tickInterval:           *tickInterval,
		rotationInterval:       *rotationInterval,
		cronReload:             *cronReload,
		drainTimeout:           *drainTimeout,
		aclPermissive:          *aclPermissive,
		cgroupRoot:             *cgroupRoot,
		requireCgroup:          *requireCgroup,
		insecureNoAuth:         *insecureNoAuth,
		mcpToken:               strings.TrimSpace(*mcpToken),
		mcpTenant:              strings.TrimSpace(*mcpTenant),
		mcpTrustedProxy:        *mcpTrustedProxy,
		trustedProxies:         trustedProxies,
		oauthRedirectURI:       oauthRedirectURI,
		mcpAuthoring:           *mcpAuthoring,
		mcpTriggers:            *mcpTriggers,
		mcpNotifications:       *mcpNotifications,
		mcpDispatch:            *mcpDispatch,
		mcpSecrets:             *mcpSecrets,
		mcpKnowledge:           *mcpKnowledge,
		mcpDiagnostics:         *mcpDiagnostics,
		mcpDataExport:          *mcpDataExport,
		mcpDataLifecycle:       *mcpDataLifecycle,
		mcpMailReconciliation:  *mcpMailReconciliation,
		mcpArtifactPublication: *mcpArtifactPublication,
		mcpCommandExecution:    *mcpCommandExecution,
		commandRunnerEnabled:   *commandRunnerEnabled,
		commandSingleTenant:    *commandSingleTenant,
		commandDockerBinary:    strings.TrimSpace(*commandDockerBinary),
		commandDockerImage:     strings.TrimSpace(*commandDockerImage),
		commandTargets:         splitCSV(*commandTargets),
		commandRunnerWorkers:   *commandRunnerWorkers,
		commandRunnerQueue:     *commandRunnerQueue,
		commandRunnerPoll:      *commandRunnerPoll,
		mode:                   *mode,
		queueArtifactRoot:      queueArtifactRoot,
		autoscale:              *autoscaleEnabled,
		autoscaleConfig:        autoscaleConfig,
	}, nil
}

// validateWorkflowCgroupConfig keeps strict workflow isolation from becoming a
// misleading per-run failure. The supervisor already fails closed when a
// configured cgroup root is unavailable; requiring an explicit root here also
// makes a malformed deployment fail before it advertises a ready daemon.
func validateWorkflowCgroupConfig(root string, required bool) error {
	if required && strings.TrimSpace(root) == "" {
		return errors.New("strict workflow cgroup isolation requires --cgroup-root (or REACTOR_CGROUP_ROOT)")
	}
	return nil
}

// validateAutoscaleCommandConfig fails before the daemon serves traffic when
// an enabled autoscaler lacks the configuration needed to launch and stop
// workers without embedding database credentials in an off-host Job spec.
func validateAutoscaleCommandConfig(distributed, enabled bool, privateRoot string) error {
	if !distributed || !enabled {
		return nil
	}
	substrate := strings.ToLower(strings.TrimSpace(envFirstOr("process", "REACTOR_AUTOSCALE_SPAWNER")))
	if substrate == "process" || substrate == "docker" {
		if _, err := parseAutoscaleWorkerConcurrency(); err != nil {
			return err
		}
	}
	switch substrate {
	case "docker", "kubernetes", "k8s":
		if strings.TrimSpace(os.Getenv("REACTOR_WORKER_IMAGE")) == "" {
			return errors.New("autoscaler requires REACTOR_WORKER_IMAGE for docker or kubernetes")
		}
		if substrate == "kubernetes" || substrate == "k8s" {
			if strings.TrimSpace(os.Getenv("REACTOR_AUTOSCALE_K8S_DB_SECRET")) == "" {
				return errors.New("kubernetes autoscaler requires REACTOR_AUTOSCALE_K8S_DB_SECRET to keep database credentials out of the Job spec")
			}
			if strings.TrimSpace(os.Getenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET")) == "" {
				return errors.New("kubernetes autoscaler requires REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET so workers can open the vault without an image-baked key")
			}
			if _, _, err := kubernetesArtifactMountConfig(privateRoot); err != nil {
				return err
			}
			if _, err := parseKubernetesWorkerResources(); err != nil {
				return err
			}
		}
		if err := autoscale.ValidateFleetID(os.Getenv("REACTOR_AUTOSCALE_FLEET_ID")); err != nil {
			return err
		}
		return nil
	case "command":
		// Custom commands must identify the detached worker they stop.
	case "process":
		return nil
	default:
		return fmt.Errorf("unknown REACTOR_AUTOSCALE_SPAWNER %q (want process|docker|kubernetes|command)", substrate)
	}
	if strings.TrimSpace(os.Getenv("REACTOR_AUTOSCALE_SPAWN_CMD")) == "" {
		return errors.New("command autoscaler requires REACTOR_AUTOSCALE_SPAWN_CMD")
	}
	stop := strings.TrimSpace(os.Getenv("REACTOR_AUTOSCALE_STOP_CMD"))
	if stop == "" {
		return errors.New("command autoscaler requires REACTOR_AUTOSCALE_STOP_CMD")
	}
	if !strings.Contains(stop, "{id}") {
		return errors.New("command autoscaler REACTOR_AUTOSCALE_STOP_CMD must contain {id}")
	}
	return nil
}

// envFirstOr returns the first set env var among keys, or def.
func envFirstOr(def string, keys ...string) string {
	if v := envFirst(keys...); v != "" {
		return v
	}
	return def
}

// mcpOAuthRedirectURI turns the operator's public dashboard origin into the
// one callback route served by Reactor. Empty configuration keeps the consent
// tool unavailable; it is safer than guessing from an MCP request Host header
// or advertising a provider callback that cannot complete.
func mcpOAuthRedirectURI(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.User != nil {
		return "", errors.New("serve: REACTOR_DASHBOARD_URL must be an absolute HTTP(S) origin without userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("serve: REACTOR_DASHBOARD_URL must be an origin without path, query, or fragment")
	}
	u.Path = "/oauth/callback"
	u.RawPath = ""
	if u.Scheme != "https" {
		if u.Scheme != "http" || !mcpOAuthLoopbackHost(u.Hostname()) {
			return "", errors.New("serve: REACTOR_DASHBOARD_URL must use https (http is allowed only for loopback)")
		}
	}
	return u.String(), nil
}

func mcpOAuthLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isPostgresURL reports whether a DB URL targets Postgres.
func isPostgresURL(u string) bool {
	return strings.HasPrefix(u, "postgres://") || strings.HasPrefix(u, "postgresql://")
}

// serveDeps holds runtime components. openServeDeps builds the serving surface;
// openWorkerDeps builds only execution dependencies. Each caller owns
// deps.db.Close().
type serveDeps struct {
	db                    *sql.DB
	journal               *journal.Journal
	credRepo              *credentials.Repo
	vaultStore            *vault.Store
	oauthStore            *oauth.Store
	registry              *registry.FileRegistry
	knowStore             *knowledge.Store
	pmGen                 *postmortem.Generator
	logBuffer             *runlogs.Buffer
	metrics               *server.Metrics
	dispatcher            *dispatcher.Dispatcher
	receiver              *webhook.Receiver
	commandWebhook        *commandwebhook.Receiver
	cronDriver            *cron.Driver
	scheduler             *supervisor.Scheduler
	cancels               *cancelreg.Registry
	rotRunner             *rotators.Runner
	graph                 *graph.Graph
	mcpSrv                *mcp.Server
	wfGen                 server.WorkflowGenerator
	notifier              *notifier.Notifier
	authStore             *auth.Store
	commandQueue          *commandrunner.Queue
	commandScheduleDriver *commandrunner.CommandScheduleDriver
	commandChains         *commandChainDispatcher
	// leaderReady is set by runServeLoop before the leader goroutine starts.
	// Local mode calls it only after cron, command schedules, and the leader
	// loops have been started. Distributed followers call it once their
	// Postgres connection is established: they can already serve HTTP/MCP and
	// enqueue work while waiting for the advisory leadership lock.
	leaderReady func()
}

// openServeDeps runs migrations + opens the DB + wires every runtime
// component. The order matters: migrations before Open so the schema
// is current before any engine binds; vault after credentials so the
// engine bridge is set up; graph build is best-effort (a startup
// failure logs but doesn't block boot).
func openServeDeps(ctx context.Context, log *slog.Logger, cfg *serveConfig) (*serveDeps, error) {
	if err := validatePrivateStateRoot(cfg.root); err != nil {
		return nil, fmt.Errorf("serve: state root: %w", err)
	}
	if cfg.queueArtifactRoot != "" {
		if err := validateWorkerArtifactRoot(cfg.queueArtifactRoot); err != nil {
			return nil, fmt.Errorf("serve: worker artifact root: %w", err)
		}
	}
	log.Info("serve: running migrations", "db", redactDB(cfg.dbURL))
	if err := migrate.Up(ctx, log, cfg.dbURL); err != nil {
		return nil, fmt.Errorf("serve: migrate: %w", err)
	}
	db, engine, err := migrate.Open(cfg.dbURL)
	if err != nil {
		return nil, fmt.Errorf("serve: open db: %w", err)
	}
	jEngine := journal.EngineSQLite
	credEngine := credentials.EngineSQLite
	vaultEngine := vault.SQLEngineSQLite
	if engine == migrate.EnginePostgres {
		jEngine = journal.EnginePostgres
		credEngine = credentials.EnginePostgres
		vaultEngine = vault.SQLEnginePostgres
	}
	j := journal.New(db, jEngine)
	if err := j.EnablePayloadEncryption(ctx, cfg.masterKey, cfg.previousMasterKey); err != nil {
		db.Close()
		return nil, fmt.Errorf("serve: journal payload key: %w", err)
	}
	// Local mode only: a fresh single-node process owns no in-flight
	// supervisors, so any run still marked "running" is orphaned from a
	// prior crash; fail it. In DISTRIBUTED mode this must NOT run -- a
	// serve restart would fail runs that healthy workers are actively
	// executing. There, dead-worker runs are requeued by the lease reaper
	// (ReapExpiredLeases) instead, which resumes them rather than failing.
	if !cfg.distributed() {
		if n, rErr := j.ReapOrphanedRuns(ctx); rErr != nil {
			db.Close()
			return nil, fmt.Errorf("serve: recover local orphaned runs: %w", rErr)
		} else if n > 0 {
			log.Info("serve: classified orphaned local runs", "count", n)
		}
	}
	credRepo := credentials.New(db, credEngine)
	authEngine := auth.EngineSQLite
	if engine == migrate.EnginePostgres {
		authEngine = auth.EnginePostgres
	}
	authStore := auth.New(db, authEngine, buildMFAOptions(log, cfg.masterKey)...)
	vaultStore, err := vault.NewStore(vault.NewSQLBackend(db, vaultEngine), cfg.masterKey, cfg.previousMasterKey)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("serve: vault: %w", err)
	}
	oauthEngine := oauth.EngineSQLite
	if engine == migrate.EnginePostgres {
		oauthEngine = oauth.EnginePostgres
	}
	oauthStore := oauth.New(db, oauthEngine, cfg.masterKey)
	// Teach the generic OAuth flow each provider's quirks (token-exchange auth
	// style, extra authorize params) from the service catalog, so adding a
	// provider that needs HTTP Basic or extra params is a catalog entry, not a
	// code change.
	oauthStore.ProfileFor = func(id string) oauth.Profile {
		if svc, ok := catalog.ByID(id); ok {
			return oauth.Profile{TokenAuthStyle: svc.TokenAuthStyle, AuthParams: svc.AuthParams}
		}
		return oauth.Profile{}
	}
	reg := registry.New(filepath.Join(cfg.root, "workflows"))

	knowStore, err := knowledge.New(filepath.Join(cfg.root, "knowledge"))
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("serve: knowledge: %w", err)
	}
	knowStore.Git = &codegen.GitCommitter{}

	pmGen := buildPostMortemGenerator(log, j, knowStore)
	logBuffer := runlogs.New(1000, 10*time.Minute)
	// Persist each run's log tail to the DB when it terminates so it
	// survives the in-memory ring's grace window (the dashboard + MCP read
	// it back). Best-effort: a failed write logs but doesn't block.
	logBuffer.OnClose = func(runID string, lines []string) {
		if err := j.SaveRunLogs(context.Background(), runID, lines); err != nil {
			log.Warn("serve: persist run logs failed", "run_id", runID, "err", err)
		}
	}
	metrics := server.NewMetrics()
	metrics.QueueDepth = j.CountQueued
	metrics.QueueClaimable = j.CountClaimableQueued
	metrics.QueueOldestAge = j.OldestQueuedAge
	metrics.WorkerCapacity = j.WorkerCapacity
	metrics.DBPoolStats = db.Stats
	notif := buildNotifier(log, cfg, j, credRepo, vaultStore)

	cancels := cancelreg.New()
	// Command runner construction happens below the dispatcher because it
	// needs the daemon's vault/credential stores. Keep a captured reference so
	// terminal callbacks can use the dedicated command-chain adapter once it is
	// wired, without exposing a partially constructed runner.
	var commandChains *commandChainDispatcher
	disp := buildDispatcher(log, cfg, j, vaultStore, reg, metrics, logBuffer, pmGen, notif, func() commandChainFire {
		return commandChains
	})
	disp.Cancels = cancels
	// Distributed mode: every dispatcher (the serve daemon AND each worker)
	// enqueues instead of executing in-process. Triggers enqueue; workers
	// claim + ExecuteRun; a worker's chained dispatch enqueues for another
	// worker to pick up. Only ExecuteRun actually runs a subprocess.
	disp.Enqueue = cfg.distributed()
	// Workflows resolve `oauth:<connection-id>` secrets to a fresh OAuth token.
	// Set on the template before schedTemplate copies it so resumed runs (and
	// the scheduler) get it too.
	disp.Sup.OAuthTokens = oauthStore
	receiver := &webhook.Receiver{
		Journal: j,
		Vault:   vaultStore,
		Disp:    disp,
		Log:     log,
	}
	cronDriver := &cron.Driver{
		Journal:        j,
		Disp:           disp,
		Log:            log,
		ReloadInterval: cfg.cronReload,
	}
	if strings.HasPrefix(cfg.dbURL, "postgres://") || strings.HasPrefix(cfg.dbURL, "postgresql://") {
		cronDriver.Listener = &cron.PgListener{DSN: cfg.dbURL, Log: log}
		log.Info("serve: cron pg LISTEN/NOTIFY subscriber enabled")
	}
	// The scheduler resumes suspended runs by re-spawning a supervisor, so
	// it needs the SAME template the dispatcher uses (Vault, ACLPermissive,
	// resource Limits) plus the log sink, otherwise resumed runs would run
	// with default ACL + no limits + no log tail. OnTerminal routes a
	// resumed run's REAL terminal status through the same notifier + chain
	// path the first spawn used (the first spawn only ever terminated as
	// "suspended").
	schedTemplate := disp.Sup
	schedTemplate.LogSink = logBuffer.Append
	scheduler := &supervisor.Scheduler{
		Journal:               j,
		Vault:                 vaultStore,
		Log:                   log,
		BinaryPath:            reg.BinaryPath,
		ArtifactPath:          reg.ArtifactPath,
		ArtifactPathForTenant: reg.TenantArtifactPath,
		IntegrityCheck: func(ctx context.Context, slug string, version journal.WorkflowVersion) error {
			tenant, err := j.WorkflowTenant(ctx, version.WorkflowID)
			if err != nil {
				return fmt.Errorf("resolve workflow tenant for source proof: %w", err)
			}
			return workflowproof.ValidateVersionForTenant(cfg.root, slug, tenant, version)
		},
		QueueArtifactCheck: disp.QueueArtifactCheck,
		TickInterval:       cfg.tickInterval,
		SupervisorTemplate: schedTemplate,
		Cancels:            cancels,
		Enqueue:            cfg.distributed(),
		OnTerminal: func(ctx context.Context, ti supervisor.TerminalInfo) {
			releaseAdmission := disp.HoldTerminalAdmission()
			defer releaseAdmission()
			handleRunTerminalWithCommandChains(ctx, log, notif, j, disp, logBuffer, dispatcher.TerminalEvent{
				RunID:        ti.RunID,
				WorkflowID:   ti.WorkflowID,
				WorkflowSlug: ti.WorkflowSlug,
				Status:       ti.Status,
				TriggerKind:  ti.TriggerKind,
				ErrorText:    ti.ErrorText,
				DryRun:       ti.DryRun,
			}, commandChains)
		},
	}
	rotRunner := &rotators.Runner{
		Repo:         credRepo,
		Vault:        vaultStore,
		Log:          log,
		TickInterval: cfg.rotationInterval,
	}
	graphBuilder := &graph.Builder{Journal: j, Credentials: credRepo, Knowledge: knowStore}
	gGraph, gErr := graphBuilder.Build(ctx)
	if gErr != nil {
		log.Warn("serve: graph build failed at startup", "err", gErr)
	}
	var commandRunnerInstance *commandrunner.Runner
	var commandQueue *commandrunner.Queue
	var commandScheduleDriver *commandrunner.CommandScheduleDriver
	var commandWebhookReceiver *commandwebhook.Receiver
	var commandTargetPolicy commandrunner.ExactTargetPolicy
	var commandCredentialMaterializer commandrunner.VaultCredentialMaterializer
	// Keep a journal-backed command-chain adapter even when the local command
	// runner is disabled. Existing active chain rows may have been created by a
	// previous deployment; the adapter must report that the runtime is
	// unavailable so terminal-effect recovery retains the source event instead
	// of acknowledging it as if no chain existed.
	commandChains = &commandChainDispatcher{Journal: j, TenantID: cfg.mcpTenant, Log: log}
	if cfg.commandRunnerEnabled {
		sandbox, sandboxErr := commandrunner.NewDockerSandbox(commandrunner.DockerConfig{
			Binary: cfg.commandDockerBinary, Image: cfg.commandDockerImage,
			MemoryBytes: 256 << 20, CPUs: "1", PIDsLimit: 64,
			TmpfsBytes: 64 << 20, MaxOutputBytes: 1 << 20,
		})
		if sandboxErr != nil {
			db.Close()
			return nil, fmt.Errorf("serve: command runner sandbox: %w", sandboxErr)
		}
		targets := make(commandrunner.ExactTargetPolicy, len(cfg.commandTargets))
		for _, target := range cfg.commandTargets {
			if strings.TrimSpace(target) != "" {
				targets[strings.TrimSpace(target)] = struct{}{}
			}
		}
		if len(targets) == 0 {
			db.Close()
			return nil, errors.New("serve: command runner requires at least one exact --command-targets entry")
		}
		commandTargetPolicy = targets
		commandCredentialMaterializer = commandrunner.VaultCredentialMaterializer{
			Grants: j, Tenants: j, Vault: vaultStore, OAuthTokens: oauthStore,
		}
		commandRunnerInstance = &commandrunner.Runner{
			Journal: j, Sandbox: sandbox, TargetPolicy: targets,
			CredentialBoundary:     commandrunner.JournalCredentialBoundary{Journal: j},
			CredentialMaterializer: commandCredentialMaterializer,
			Enabled:                true,
			ActorProvider: func(runCtx context.Context) (string, error) {
				user, ok := server.UserFromContext(runCtx)
				if !ok {
					return "", errors.New("authenticated actor is required")
				}
				if strings.TrimSpace(user.ID) != "" {
					return user.ID, nil
				}
				if strings.TrimSpace(user.Username) != "" {
					return user.Username, nil
				}
				return "", errors.New("authenticated actor identity is empty")
			},
		}
		commandRunnerInstance.CapabilitiesProvider = func(runCtx context.Context, definition commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			caps := daemonCommandExecutionCapabilities(runCtx, definition)
			caps.FeatureEnabled = cfg.commandRunnerEnabled
			caps.SingleTenant = cfg.commandSingleTenant
			caps.SandboxProfileReady = sandbox.Profile().Valid()
			caps.VaultBoundaryReady = true
			caps.CredentialsSupported = commandDefinitionCredentialSupport(runCtx, cfg.mcpTenant, definition, commandCredentialMaterializer)
			caps.OutputLimitsReady = true
			caps.AuditReady = true
			caps.RunnerReady = true
			return caps, nil
		}
		// Scheduled fires have no interactive HTTP session. They use the same
		// daemon-owned deployment, sandbox, resolver, output, and audit facts;
		// Runner supplies the separate durable trigger authorization only after
		// it has verified the exact schedule receipt binding.
		commandRunnerInstance.ScheduledCapabilitiesProvider = func(runCtx context.Context, definition commandautomations.Definition) (commandautomations.ExecutionCapabilities, error) {
			caps := commandautomations.ExecutionCapabilities{}
			caps.FeatureEnabled = cfg.commandRunnerEnabled
			caps.SingleTenant = cfg.commandSingleTenant
			caps.SandboxProfileReady = sandbox.Profile().Valid()
			caps.VaultBoundaryReady = true
			caps.CredentialsSupported = commandDefinitionCredentialSupport(runCtx, cfg.mcpTenant, definition, commandCredentialMaterializer)
			caps.OutputLimitsReady = true
			caps.AuditReady = true
			caps.RunnerReady = true
			return caps, nil
		}
		log.Warn("serve: command runner enabled; only exact configured targets and plans passing credential tenant, grant, and resolver checks can execute")
		commandQueue, err = commandrunner.NewQueue(commandRunnerInstance, j, commandrunner.QueueConfig{
			Workers: cfg.commandRunnerWorkers, Capacity: cfg.commandRunnerQueue,
			PollInterval: cfg.commandRunnerPoll, TenantID: cfg.mcpTenant,
			WorkerPrefix: "mcp-command-runner",
			OnError: func(queueErr error) {
				log.Warn("serve: command runner queue error", "err", queueErr)
			},
		})
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("serve: command runner queue: %w", err)
		}
		commandScheduleDriver = &commandrunner.CommandScheduleDriver{
			Journal: j, Runner: commandRunnerInstance, Queue: commandQueue,
			TenantID: cfg.mcpTenant, Log: log, ReloadInterval: cfg.cronReload,
		}
		commandWebhookReceiver = &commandwebhook.Receiver{
			Journal: j, Vault: vaultStore, Runner: commandRunnerInstance, Queue: commandQueue,
			TenantID: cfg.mcpTenant, Log: log,
		}
		commandChains.Runner = commandRunnerInstance
		commandChains.Queue = commandQueue
	}
	mcpSrv := &mcp.Server{
		Info: mcp.ServerInfo{
			Name:    "reactor",
			Version: Version,
		},
		MCPCalls:           metrics,
		Journal:            j,
		Credentials:        credRepo,
		OAuth:              oauthStore,
		OAuthRedirectURI:   cfg.oauthRedirectURI,
		Knowledge:          knowStore,
		Graph:              gGraph,
		Log:                log,
		StateRoot:          cfg.root,
		WorkerArtifactRoot: cfg.queueArtifactRoot,
		TenantIDFromContext: func(ctx context.Context) string {
			if user, ok := server.UserFromContext(ctx); ok {
				return user.TenantID
			}
			return journal.DefaultTenant
		},
		ActorIDFromContext: func(ctx context.Context) string {
			if user, ok := server.UserFromContext(ctx); ok {
				if user.ID != "" {
					return user.ID
				}
				return user.Username
			}
			return "mcp"
		},
		MailReconciliationAuthorized: func(ctx context.Context) bool {
			user, ok := server.UserFromContext(ctx)
			return ok && user.IsAdmin()
		},
		ArtifactPublicationAuthorized: func(ctx context.Context) bool {
			user, ok := server.UserFromContext(ctx)
			return ok && user.IsAdmin()
		},
		AllowedOrigins: splitCSV(os.Getenv("REACTOR_MCP_ALLOWED_ORIGINS")),
		// The preflight provider projects authenticated admin and fresh session
		// step-up facts and, when the separately configured runner is present,
		// reports its fixed sandbox/audit capabilities. The dedicated MCP bearer
		// has no SessionState and therefore can never satisfy the step-up gate by
		// bearer possession alone.
		CommandExecutionCapabilities: func(capCtx context.Context, definition commandautomations.Definition) commandautomations.ExecutionCapabilities {
			caps := daemonCommandExecutionCapabilities(capCtx, definition)
			caps.FeatureEnabled = cfg.commandRunnerEnabled
			caps.SingleTenant = cfg.commandSingleTenant
			caps.OutputLimitsReady = commandRunnerInstance != nil
			caps.AuditReady = true
			caps.RunnerReady = commandRunnerInstance != nil && cfg.mcpCommandExecution
			if commandRunnerInstance != nil {
				caps.SandboxProfileReady = commandRunnerInstance.Sandbox.Profile().Valid()
				caps.VaultBoundaryReady = true
				caps.CredentialsSupported = commandDefinitionCredentialSupport(capCtx, cfg.mcpTenant, definition, commandCredentialMaterializer)
			}
			return caps
		},
		CommandTenantAllowed: func(capCtx context.Context) bool {
			tenantID := journal.DefaultTenant
			if user, ok := server.UserFromContext(capCtx); ok && strings.TrimSpace(user.TenantID) != "" {
				tenantID = strings.TrimSpace(user.TenantID)
			}
			return tenantID == cfg.mcpTenant
		},
		CommandCredentialResolverReady: func(checkCtx context.Context, credentialID string) bool {
			// The MCP readiness projection must not call a broker-only OAuth
			// connection usable merely because an OAuth store is configured.
			// Tenant ownership and command grants are checked separately; this
			// policy probe never returns a credential value.
			tenantID := cfg.mcpTenant
			if user, ok := server.UserFromContext(checkCtx); ok && strings.TrimSpace(user.TenantID) != "" {
				tenantID = strings.TrimSpace(user.TenantID)
			}
			return commandRunnerInstance != nil && commandCredentialMaterializer.SupportsForTenant(checkCtx, tenantID, credentialID)
		},
		RunCommandAutomation: func(runCtx context.Context, request mcp.CommandRunAutomationRequest) (journal.CommandRun, error) {
			if commandRunnerInstance == nil || commandQueue == nil {
				return journal.CommandRun{}, errors.New("command runner is not configured")
			}
			tenantID := journal.DefaultTenant
			if user, ok := server.UserFromContext(runCtx); ok && strings.TrimSpace(user.TenantID) != "" {
				tenantID = user.TenantID
			}
			if tenantID != cfg.mcpTenant {
				return journal.CommandRun{}, fmt.Errorf("command runner is bound to tenant %q", cfg.mcpTenant)
			}
			req := commandrunner.Request{
				TenantID: tenantID, AutomationID: request.AutomationID, Version: request.Version,
				RunID: request.RunID, RetryOf: request.RetryOf, WorkerID: "mcp-command-admission", Admission: request.Admission,
			}
			result, err := commandRunnerInstance.Admit(runCtx, req)
			if err != nil {
				return journal.CommandRun{}, err
			}
			if result.Run.Status == journal.CommandRunQueued {
				// The durable row is already visible even if the bounded in-memory
				// channel is full; the recovery poller will pick it up later.
				enqueueErr := commandQueue.Enqueue(context.Background(), reqWithRun(req, result.Run))
				if enqueueErr != nil && !errors.Is(enqueueErr, commandrunner.ErrQueueFull) {
					return journal.CommandRun{}, fmt.Errorf("command runner queue admission: %w", enqueueErr)
				}
				if errors.Is(enqueueErr, commandrunner.ErrQueueFull) {
					log.Warn("serve: command runner queue full; durable recovery will retry", "run_id", result.Run.ID)
				}
			}
			return result.Run, nil
		},
		CancelCommandRun: func(runCtx context.Context, request mcp.CommandRunCancelRequest) (journal.CommandRun, string, error) {
			if runCtx == nil {
				runCtx = context.Background()
			}
			tenantID := journal.DefaultTenant
			if user, ok := server.UserFromContext(runCtx); ok && strings.TrimSpace(user.TenantID) != "" {
				tenantID = user.TenantID
			}
			if tenantID != cfg.mcpTenant {
				return journal.CommandRun{}, "", fmt.Errorf("command runner is bound to tenant %q", cfg.mcpTenant)
			}
			cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(runCtx), 5*time.Second)
			defer cancel()
			outcome, err := j.CancelCommandRunForTenant(cancelCtx, tenantID, request.RunID, request.Reason)
			if err != nil {
				return journal.CommandRun{}, outcome, err
			}
			// Fence the durable row before interrupting a local worker. A worker in
			// another process is fenced by the cleared claim token and lease checks.
			// Do not interrupt a worker that already reached a terminal state while
			// this request was racing it.
			if outcome == journal.CommandCancelDone && commandQueue != nil {
				commandQueue.Cancel(tenantID, request.RunID)
			}
			run, err := j.GetCommandRunForTenant(cancelCtx, tenantID, request.RunID)
			if err != nil {
				return journal.CommandRun{}, outcome, err
			}
			return run, outcome, nil
		},
		CommandAutomationSchedules: j,
		CommandAutomationWebhooks:  j,
		CommandAutomationWebhookRuntimeReady: func(context.Context) bool {
			return commandWebhookReceiver != nil
		},
		CommandAutomationChains: j,
		CommandAutomationChainRuntimeReady: func(context.Context) bool {
			return commandChains != nil && commandChains.Runner != nil && commandChains.Queue != nil
		},
		CommandTargetAllowed: func(targetCtx context.Context, target string) bool {
			if commandRunnerInstance == nil || !cfg.mcpCommandExecution {
				return false
			}
			allowed, _ := commandTargetPolicy.Allow(targetCtx, "", target)
			return allowed
		},
		// The HTTP route is mounted behind the server's authentication and
		// admin middleware. Capabilities remain independently opt-in so a
		// normal serve process exposes read-only MCP even though it owns the
		// dispatcher and vault.
		Scopes: &mcp.WriteScopes{
			Authoring:           cfg.mcpAuthoring,
			Triggers:            cfg.mcpTriggers,
			Notifications:       cfg.mcpNotifications,
			Dispatch:            cfg.mcpDispatch,
			Secrets:             cfg.mcpSecrets,
			CommandExecution:    cfg.mcpCommandExecution,
			Knowledge:           cfg.mcpKnowledge,
			Diagnostics:         cfg.mcpDiagnostics,
			DataExport:          cfg.mcpDataExport,
			DataLifecycle:       cfg.mcpDataLifecycle,
			MailReconciliation:  cfg.mcpMailReconciliation,
			ArtifactPublication: cfg.mcpArtifactPublication,
		},
	}
	var graphRefreshMu sync.Mutex
	mcpSrv.GraphRefresh = func(refreshCtx context.Context) error {
		graphRefreshMu.Lock()
		defer graphRefreshMu.Unlock()
		next, err := graphBuilder.Build(refreshCtx)
		if err != nil {
			return err
		}
		if gGraph == nil {
			gGraph = next
			mcpSrv.Graph = gGraph
			return nil
		}
		gGraph.ReplaceFrom(next)
		return nil
	}
	// Wire the same dispatcher admission path used by the dashboard. The
	// closure is present even when the dispatch scope is disabled; Scopes is
	// non-nil, so no consequential tool is advertised until its explicit flag
	// is enabled. This keeps HTTP MCP and the dashboard on one execution path
	// for enabled checks, quotas, rate limits, artifact pins, leases, and
	// terminal handling.
	mcpSrv.RetryDeadLetter = disp.RetryDeadLetter
	mcpSrv.ReconcileCron = cronDriver.Reconcile
	if commandScheduleDriver != nil {
		mcpSrv.ReconcileCommandSchedules = commandScheduleDriver.Reconcile
	}
	mcpSrv.TestDispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
		tenantID := journal.DefaultTenant
		if user, ok := server.UserFromContext(ctx); ok && user.TenantID != "" {
			tenantID = user.TenantID
		}
		wfID, err := j.WorkflowIDBySlugInTenant(ctx, slug, tenantID)
		if err != nil {
			if errors.Is(err, journal.ErrNotFound) {
				return "", fmt.Errorf("test_workflow: unknown slug %q", slug)
			}
			return "", err
		}
		trg := journal.Trigger{WorkflowID: wfID, Kind: journal.TriggerManual, Config: json.RawMessage(`{}`), State: "active"}
		return disp.DispatchTest(ctx, trg, payload)
	}
	mcpSrv.Dispatch = func(ctx context.Context, slug string, payload json.RawMessage) (string, error) {
		tenantID := journal.DefaultTenant
		if user, ok := server.UserFromContext(ctx); ok && user.TenantID != "" {
			tenantID = user.TenantID
		}
		wfID, err := j.WorkflowIDBySlugInTenant(ctx, slug, tenantID)
		if err != nil {
			if errors.Is(err, journal.ErrNotFound) {
				return "", fmt.Errorf("dispatch_workflow: unknown slug %q", slug)
			}
			return "", err
		}
		trg := journal.Trigger{
			WorkflowID: wfID,
			Kind:       journal.TriggerManual,
			Config:     json.RawMessage(`{}`),
			State:      "active",
		}
		return disp.DispatchManual(ctx, trg, payload)
	}
	mcpSrv.DispatchIdempotent = func(ctx context.Context, slug string, payload json.RawMessage, key string) (string, error) {
		tenantID := journal.DefaultTenant
		if user, ok := server.UserFromContext(ctx); ok && user.TenantID != "" {
			tenantID = user.TenantID
		}
		wfID, err := j.WorkflowIDBySlugInTenant(ctx, slug, tenantID)
		if err != nil {
			if errors.Is(err, journal.ErrNotFound) {
				return "", fmt.Errorf("dispatch_workflow: unknown slug %q", slug)
			}
			return "", err
		}
		trg := journal.Trigger{WorkflowID: wfID, Kind: journal.TriggerManual, Config: json.RawMessage(`{}`), State: "active"}
		return disp.DispatchManualIdempotent(ctx, trg, payload, key)
	}
	if pmGen != nil {
		mcpSrv.PostMortem = func(pmCtx context.Context, runID string) (string, error) {
			tenantID := journal.DefaultTenant
			if mcpSrv.TenantIDFromContext != nil {
				if scoped := strings.TrimSpace(mcpSrv.TenantIDFromContext(pmCtx)); scoped != "" {
					tenantID = scoped
				}
			}
			return pmGen.GenerateForTenant(pmCtx, runID, tenantID)
		}
	}
	wfGen := buildWorkflowGenerator(log, cfg)
	return &serveDeps{
		db:                    db,
		journal:               j,
		credRepo:              credRepo,
		vaultStore:            vaultStore,
		oauthStore:            oauthStore,
		registry:              reg,
		knowStore:             knowStore,
		pmGen:                 pmGen,
		logBuffer:             logBuffer,
		metrics:               metrics,
		dispatcher:            disp,
		receiver:              receiver,
		commandWebhook:        commandWebhookReceiver,
		cronDriver:            cronDriver,
		scheduler:             scheduler,
		cancels:               cancels,
		rotRunner:             rotRunner,
		graph:                 gGraph,
		mcpSrv:                mcpSrv,
		wfGen:                 wfGen,
		notifier:              notif,
		authStore:             authStore,
		commandQueue:          commandQueue,
		commandScheduleDriver: commandScheduleDriver,
		commandChains:         commandChains,
	}, nil
}

func reqWithRun(req commandrunner.Request, run journal.CommandRun) commandrunner.Request {
	req.RunID = run.ID
	req.Admission = run.Admission
	return req
}

// daemonCommandExecutionCapabilities exposes only authentication facts that
// the daemon can prove for this request. The caller adds the separately
// configured runner, target, sandbox, output, audit, feature, and tenant
// capabilities; this helper never authorizes execution on its own. In
// particular, a dedicated MCP bearer has no fresh session step-up state.
func daemonCommandExecutionCapabilities(ctx context.Context, _ commandautomations.Definition) commandautomations.ExecutionCapabilities {
	user, authenticated := server.UserFromContext(ctx)
	elevated := false
	if state, ok := server.SessionStateFromContext(ctx); ok {
		elevated = state.IsElevated()
	}
	return commandExecutionCapabilitiesFor(user, authenticated, elevated)
}

func commandDefinitionCredentialSupport(ctx context.Context, tenantID string, definition commandautomations.Definition, materializer commandrunner.VaultCredentialMaterializer) bool {
	for _, step := range definition.Steps {
		for _, id := range step.CredentialIDs {
			if !materializer.SupportsForTenant(ctx, tenantID, id) {
				return false
			}
		}
	}
	return true
}

func commandExecutionCapabilitiesFor(user auth.User, authenticated, elevated bool) commandautomations.ExecutionCapabilities {
	return commandautomations.ExecutionCapabilities{
		AdminAuthorized:  authenticated && user.IsAdmin(),
		StepUpAuthorized: authenticated && elevated,
	}
}

// runRetentionLoop sweeps ephemeral rows hourly and, when explicitly enabled,
// advances bounded run-history retention every minute. Each history tick has
// a fixed transaction/parent-run cap, so a large backlog resumes on later
// ticks (a run can still own many child rows).
func runRetentionLoop(ctx context.Context, log *slog.Logger, deps *serveDeps) {
	webhookRetain := time.Duration(envIntFirst("REACTOR_WEBHOOK_DEDUP_RETAIN_HOURS", "", 720)) * time.Hour
	// Run-history retention is OPT-IN (0 = keep forever, the historical
	// default): deleting run history is a product/GDPR decision, not a silent
	// one. When set, finished runs older than N days are purged.
	runRetentionDays := envIntFirst("REACTOR_RUN_RETENTION_DAYS", "", 0)
	// A duration overflow can turn a distant-past cutoff into a future one
	// and erase fresh terminal history. Invalid values fail closed.
	const maxRunRetentionDays = int((1<<63 - 1) / int64(24*time.Hour))
	if runRetentionDays < 0 || runRetentionDays > maxRunRetentionDays {
		log.Warn("serve: invalid run retention days; history purge disabled", "days", runRetentionDays)
		runRetentionDays = 0
	}
	ephemeralTicker := time.NewTicker(time.Hour)
	defer ephemeralTicker.Stop()
	var historyTick <-chan time.Time
	if runRetentionDays > 0 {
		historyTicker := time.NewTicker(time.Minute)
		defer historyTicker.Stop()
		historyTick = historyTicker.C
	}
	runRetentionLoopOnTicks(ctx, log, deps, webhookRetain, runRetentionDays, ephemeralTicker.C, historyTick)
}

// runRetentionLoopOnTicks keeps the actual sweeps testable with supplied ticks.
// Production supplies hourly and minutely tickers above; historyTick is nil
// while run retention is disabled.
func runRetentionLoopOnTicks(ctx context.Context, log *slog.Logger, deps *serveDeps, webhookRetain time.Duration, runRetentionDays int, ephemeralTick, historyTick <-chan time.Time) {
	sweepEphemeral := func() {
		if n, err := deps.authStore.SweepExpiredSessions(ctx); err != nil {
			log.Warn("serve: sweep expired sessions failed", "err", err)
		} else if n > 0 {
			log.Info("serve: swept expired sessions", "count", n)
		}
		if n, err := deps.authStore.SweepExpiredChallenges(ctx); err != nil {
			log.Warn("serve: sweep expired webauthn challenges failed", "err", err)
		} else if n > 0 {
			log.Info("serve: swept expired webauthn challenges", "count", n)
		}
		if err := deps.journal.PurgeOldWebhookDeliveries(ctx, webhookRetain); err != nil {
			log.Warn("serve: purge old webhook deliveries failed", "err", err)
		}
	}
	sweepHistory := func() {
		cutoff := time.Now().UTC().Add(-time.Duration(runRetentionDays) * 24 * time.Hour)
		n, err := deps.journal.PurgeTerminalRunsOlderThan(ctx, cutoff)
		if n > 0 {
			log.Info("serve: purged old runs (retention)", "count", n, "older_than_days", runRetentionDays)
		}
		if err != nil && ctx.Err() == nil {
			log.Warn("serve: run retention purge failed", "err", err)
		}
	}
	sweepEphemeral()
	if runRetentionDays > 0 {
		sweepHistory()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ephemeralTick:
			sweepEphemeral()
		case <-historyTick:
			if runRetentionDays > 0 {
				sweepHistory()
			}
		}
	}
}

// runCommandLeaseLoop requeues command runs whose worker process disappeared.
// It is separate from hourly retention because a command lease is an
// execution-safety fence, not a storage-retention task.
func runCommandLeaseLoop(ctx context.Context, log *slog.Logger, deps *serveDeps) {
	sweep := func() {
		n, err := deps.journal.ReapExpiredCommandRunLeases(ctx)
		if err != nil {
			log.Warn("serve: reap expired command run leases failed", "err", err)
		} else if n > 0 {
			log.Info("serve: requeued expired command run leases", "count", n)
		}
	}
	sweep()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}

// runTerminalEffectLoop recovers notification and workflow-complete chain
// handoffs whose run status committed just before a process crash. The
// receipt is claimed with a lease and acknowledged only after the shared
// terminal path returns, so recovery is at-least-once and bounded.
func runTerminalEffectLoop(ctx context.Context, log *slog.Logger, deps *serveDeps) {
	process := func() {
		effects, err := deps.journal.ClaimTerminalEffects(ctx, 32, 2*time.Minute)
		if err != nil {
			log.Warn("serve: claim terminal effects failed", "err", err)
			return
		}
		for _, effect := range effects {
			event, err := deps.journal.GetTerminalEffectEvent(ctx, effect.RunID)
			if err != nil {
				if releaseErr := deps.journal.ReleaseTerminalEffectForClaim(context.WithoutCancel(ctx), effect, err.Error()); releaseErr != nil && !errors.Is(releaseErr, journal.ErrTerminalEffectClaimLost) {
					log.Warn("serve: release terminal effect after reconstruction failure failed", "run_id", effect.RunID, "err", releaseErr)
				}
				log.Warn("serve: reconstruct terminal effect failed", "run_id", effect.RunID, "err", err)
				continue
			}
			// A DLQ retry can reopen the same run id while an older terminal
			// receipt is being recovered. Do not acknowledge that receipt while
			// the run is nonterminal or has a different final status; the final
			// transition will refresh the receipt and make it eligible again.
			if event.Status != effect.Status {
				if releaseErr := deps.journal.ReleaseTerminalEffectForClaim(context.WithoutCancel(ctx), effect, "run status changed before terminal effect delivery"); releaseErr != nil && !errors.Is(releaseErr, journal.ErrTerminalEffectClaimLost) {
					log.Warn("serve: release terminal effect after status change failed", "run_id", effect.RunID, "err", releaseErr)
				}
				continue
			}
			handleRunTerminalWithCommandChains(ctx, log, deps.notifier, deps.journal, deps.dispatcher, deps.logBuffer, dispatcher.TerminalEvent{
				RunID:                    event.RunID,
				WorkflowID:               event.WorkflowID,
				WorkflowSlug:             event.WorkflowSlug,
				Status:                   event.Status,
				TriggerKind:              event.TriggerKind,
				ErrorText:                event.ErrorText,
				TerminalEffectClaimedAt:  effect.ClaimedAt,
				TerminalEffectClaimToken: effect.ClaimToken,
			}, deps.commandChains)
		}
	}
	process()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			process()
		}
	}
}

// runCancelWatcher honours cross-process cancellation requests. The CLI
// and MCP run outside the daemon, so they set runs.cancel_requested; this
// loop observes that flag and either cancels the live subprocess (running
// here) or finalizes a suspended run so the scheduler never resumes it.
// In-daemon dashboard cancels go straight through the registry, so this
// is the backstop for the cross-process path + the running->suspended
// race. Polls every 2s (well under the prompt-cache window) so cancels
// feel near-instant without hammering the DB.
func runCancelWatcher(ctx context.Context, log *slog.Logger, deps *serveDeps) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	tick := func() {
		ids, err := deps.journal.ListCancelRequestedActive(ctx)
		if err != nil {
			log.Warn("serve: cancel watcher list failed", "err", err)
			return
		}
		for _, id := range ids {
			if deps.cancels.Cancel(id) {
				log.Info("serve: cancelled live run on request", "run_id", id)
				continue
			}
			// Not executing here. Only finalize when no distributed lease is
			// present; another worker's live claim must persist cancellation
			// with its exact owner token.
			if _, err := deps.journal.FinalizeCancelIfUnleased(ctx, id); err != nil {
				log.Warn("serve: finalize cancel failed", "run_id", id, "err", err)
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// runCanceller is the server's RunCanceller: it records the request in the
// DB (so it survives + works for suspended runs) and, when the run is
// executing on this daemon, cancels it in-process for instant feedback.
type runCanceller struct {
	j       *journal.Journal
	cancels *cancelreg.Registry
}

func (c runCanceller) Cancel(ctx context.Context, runID string) (string, error) {
	outcome, err := c.j.RequestRunCancel(ctx, runID)
	if err != nil {
		return outcome, err
	}
	if outcome == journal.CancelRequested {
		// Running: kill the live subprocess now if it is ours; the watcher
		// is the backstop if it is not (or for a later race).
		c.cancels.Cancel(runID)
	}
	return outcome, nil
}

// buildPostMortemGenerator requires explicit diagnostic-egress opt-in as well
// as an Anthropic credential. The dispatcher gracefully skips generation when
// either condition is absent.
func buildPostMortemGenerator(log *slog.Logger, j *journal.Journal, knowStore *knowledge.Store) *postmortem.Generator {
	if !aiPostmortemEnabled() {
		log.Info("serve: post-mortem auto-generation disabled (explicit AI egress opt-in not set)")
		return nil
	}
	anth, err := codegen.NewAnthropicFromEnv()
	if err != nil {
		log.Info("serve: post-mortem auto-generation disabled (ANTHROPIC_API_KEY not set)")
		return nil
	}
	log.Info("serve: post-mortem auto-generation enabled (identifiers are redacted and Step errors synthesized before egress)")
	return &postmortem.Generator{
		Anthropic: anth,
		Journal:   j,
		Knowledge: knowStore,
		Log:       log,
	}
}

// buildDispatcher wires the dispatcher + supervisor template. Pulled
// out so the run-loop wiring is one focused block; the OnLog +
// OnTerminal + OnDeadLetter callbacks live here so the lifecycle
// rules are colocated.
func buildDispatcher(
	log *slog.Logger,
	cfg *serveConfig,
	j *journal.Journal,
	vaultStore *vault.Store,
	reg *registry.FileRegistry,
	metrics *server.Metrics,
	logBuffer *runlogs.Buffer,
	pmGen *postmortem.Generator,
	notif *notifier.Notifier,
	commandChainProviders ...func() commandChainFire,
) *dispatcher.Dispatcher {
	// Declare disp up-front so the OnTerminal closure can call
	// disp.Dispatch when chain-firing downstream workflows. The
	// dispatcher's lifecycle methods are safe to call against the
	// same instance that invoked OnTerminal: Dispatch spawns a
	// fresh inFlight goroutine which the drain path will wait on.
	disp := &dispatcher.Dispatcher{
		Journal:               j,
		Resolver:              &dispatcher.SQLResolver{Journal: j},
		BinaryPath:            reg.BinaryPath,
		ArtifactPath:          reg.ArtifactPath,
		ArtifactPathForTenant: reg.TenantArtifactPath,
		IntegrityCheck: func(ctx context.Context, slug string, version journal.WorkflowVersion) error {
			tenant, err := j.WorkflowTenant(ctx, version.WorkflowID)
			if err != nil {
				return fmt.Errorf("resolve workflow tenant for source proof: %w", err)
			}
			return workflowproof.ValidateVersionForTenant(cfg.executionArtifactRoot(), slug, tenant, version)
		},
		Log:           log,
		Counters:      metrics,
		MaxConcurrent: envIntFirst("REACTOR_MAX_CONCURRENT_RUNS", "", 32),
		Sup: supervisor.Supervisor{
			Vault:            vaultStore,
			ACLPermissive:    cfg.aclPermissive,
			SignalSigningKey: cfg.masterKey,
			Limits: supervisor.ResourceLimits{
				CgroupRoot:    cfg.cgroupRoot,
				RequireCgroup: cfg.requireCgroup,
			},
		},
		OnLog: func(runID, line string) {
			logBuffer.Append(runID, line)
		},
		OnStart: logBuffer.Begin,
	}
	if cfg.queueArtifactRoot != "" {
		disp.QueueArtifactCheck = func(ctx context.Context, slug string, version journal.WorkflowVersion) error {
			tenant, err := j.WorkflowTenant(ctx, version.WorkflowID)
			if err != nil {
				return fmt.Errorf("resolve workflow tenant for worker artifact proof: %w", err)
			}
			return workflowproof.ValidateVersionForTenant(cfg.queueArtifactRoot, slug, tenant, version)
		}
	}
	commandChains := func() commandChainFire {
		if len(commandChainProviders) == 0 || commandChainProviders[0] == nil {
			return nil
		}
		return commandChainProviders[0]()
	}
	disp.OnTerminal = func(ctx context.Context, ev dispatcher.TerminalEvent) {
		releaseAdmission := disp.HoldTerminalAdmission()
		defer releaseAdmission()
		handleRunTerminalWithCommandChains(ctx, log, notif, j, disp, logBuffer, ev, commandChains())
	}
	if pmGen != nil {
		disp.OnDeadLetter = func(ctx context.Context, runID string) {
			// Resolve the run's tenant before sending diagnostics to the model. The
			// dispatcher callback is internal, but Generate's legacy unscoped path
			// would otherwise make a cross-tenant read possible if a run identifier
			// were ever reused or a malformed legacy row reached the DLQ hook.
			run, lookupErr := j.GetRun(ctx, runID)
			if lookupErr != nil {
				log.Warn("serve: post-mortem run lookup failed", "run_id", runID, "err", lookupErr)
				return
			}
			var id string
			var err error
			if strings.TrimSpace(run.TenantID) == "" {
				// Preserve compatibility with pre-tenant legacy runs; the scoped
				// path above remains the default for all current rows.
				id, err = pmGen.Generate(ctx, runID)
			} else {
				id, err = pmGen.GenerateForTenant(ctx, runID, run.TenantID)
			}
			if err != nil {
				log.Warn("serve: post-mortem generation failed", "run_id", runID, "err", err)
				return
			}
			log.Info("serve: post-mortem written", "run_id", runID, "entry_id", id)
		}
	}
	return disp
}

// buildNotifier returns a Notifier with Slack + generic-webhook + email
// senders registered. The dashboard URL (used to render "Open run"
// buttons in alert bodies) is read from REACTOR_DASHBOARD_URL with a
// fallback to the listen addr; operators behind a reverse proxy set
// the env var explicitly.
func buildNotifier(log *slog.Logger, cfg *serveConfig, j *journal.Journal, credRepo *credentials.Repo, vaultStore *vault.Store) *notifier.Notifier {
	dashURL := envFirst("REACTOR_DASHBOARD_URL")
	if dashURL == "" && cfg.addr != "" {
		dashURL = "http://" + cfg.addr
	}
	return notifier.New(j, log).
		WithSender(notifier.NewSlackSender()).
		WithSender(notifier.NewWebhookSender()).
		WithSender(notifier.NewEmailSender()).
		WithDashboardURL(dashURL).
		// Resolve referenced SMTP passwords and webhook credentials from the
		// vault only at send time. New channel configs are also sealed by the
		// journal before they are stored.
		WithSecretResolver(func(ctx context.Context, tenantID, credentialID string) (string, error) {
			if credRepo == nil {
				return "", fmt.Errorf("notification credential repository unavailable")
			}
			if _, err := credRepo.GetMetadataByTenant(ctx, credentialID, tenantID); err != nil {
				return "", fmt.Errorf("notification credential is unavailable to this tenant: %w", err)
			}
			sec, err := vaultStore.Get(ctx, credentialID)
			if err != nil {
				return "", err
			}
			return string(sec.Reveal()), nil
		})
}

// buildWorkflowGenerator returns the server-side adapter wrapping
// codegen.Generator when ANTHROPIC_API_KEY is set; otherwise nil so
// Mount skips the /generate route.
func buildWorkflowGenerator(log *slog.Logger, cfg *serveConfig) server.WorkflowGenerator {
	anth, err := codegen.NewAnthropicFromEnv()
	if err != nil {
		log.Info("serve: dashboard codegen prompt bar disabled (ANTHROPIC_API_KEY not set)")
		return nil
	}
	log.Info("serve: dashboard codegen prompt bar enabled")
	return generatorAdapter{gen: &codegen.Generator{
		Anthropic:    anth,
		Log:          log,
		WorkflowsDir: filepath.Join(cfg.root, "generated-workflows"),
		MaxRetries:   3,
	}}
}

// buildHTTPServer assembles the server.Server with every capability
// wired. Capabilities the daemon has are passed in; nil-valued
// optional fields are left as zero values so Mount's per-feature
// helpers skip their corresponding route groups.
func buildHTTPServer(log *slog.Logger, cfg *serveConfig, deps *serveDeps) *server.Server {
	srv := &server.Server{
		Journal:        deps.journal,
		Credentials:    deps.credRepo,
		OAuth:          deps.oauthStore,
		Vault:          deps.vaultStore,
		Rotator:        deps.rotRunner,
		Generator:      deps.wfGen,
		MCPHandler:     deps.mcpSrv,
		Metrics:        deps.metrics,
		ManualDispatch: deps.dispatcher,
		Notifier:       deps.notifier,
		Auth:           deps.authStore,
		MCPBearerToken: cfg.mcpToken,
		MCPBearerUser: auth.User{
			ID:       "mcp-http",
			Username: "mcp-http",
			Role:     auth.RoleAdmin,
			TenantID: cfg.mcpTenant,
		},
		DLQRetry:       deps.dispatcher,
		RunCanceller:   runCanceller{j: deps.journal, cancels: deps.cancels},
		KnowledgeWrite: knowledgeAdapter{store: deps.knowStore, log: log},
		WorkflowRegister: workflowRegistrarAdapter{
			registry:  deps.registry,
			journal:   deps.journal,
			root:      cfg.root,
			committer: &codegen.GitCommitter{},
			log:       log,
		},
		State:              cfg.root,
		WorkerArtifactRoot: cfg.queueArtifactRoot,
		Registry:           deps.registry,
		Knowledge:          deps.knowStore,
		Graph:              deps.graph,
		Webhook:            deps.receiver,
		CommandWebhook:     deps.commandWebhook,
		Log:                log,
		Version:            Version,
		WorkflowsRoot:      filepath.Join(cfg.root, "workflows"),
		CodeValidator:      editValidator{},
		CodeCommitter:      &codegen.GitCommitter{},
		LogBuffer:          deps.logBuffer,
		BasicAuth: server.BasicAuthConfig{
			User:           envFirst("REACTOR_BASIC_AUTH_USER", "ARACHNE_BASIC_AUTH_USER"),
			PasswordSHA256: envFirst("REACTOR_BASIC_AUTH_PASSWORD_SHA256", "ARACHNE_BASIC_AUTH_PASSWORD_SHA256"),
			AllowNoAuth:    cfg.insecureNoAuth,
			Realm:          "reactor",
		},
		RateLimit: server.RateLimitConfig{
			Burst:  envIntFirst("REACTOR_RATE_BURST", "ARACHNE_RATE_BURST", 60),
			Refill: envFloatFirst("REACTOR_RATE_REFILL", "ARACHNE_RATE_REFILL", 10),
		},
		TrustedProxies: cfg.trustedProxies,
		// Force the session cookie's Secure flag when the daemon sits
		// behind a TLS-terminating proxy (r.TLS is nil there). Opt in via
		// REACTOR_SECURE_COOKIES=1 or simply by configuring an https
		// dashboard URL. Direct-TLS deploys get Secure regardless.
		SecureCookies: os.Getenv("REACTOR_SECURE_COOKIES") == "1" ||
			strings.HasPrefix(envFirst("REACTOR_DASHBOARD_URL"), "https://"),
	}
	if srv.BasicAuth.User == "" && srv.BasicAuth.PasswordSHA256 == "" && !cfg.insecureNoAuth {
		log.Warn("serve: dashboard auth credentials not configured; HTTP routes (except /healthz + /webhook/* + /command-webhook/* + /signal/*) will return 503 until REACTOR_BASIC_AUTH_USER + REACTOR_BASIC_AUTH_PASSWORD_SHA256 are set or --insecure-no-auth is passed")
	}
	if cfg.insecureNoAuth {
		// The wide-open state is the one that most deserves a warning, yet it
		// used to log nothing. Make it LOUD on every boot so an inherited
		// REACTOR_INSECURE_NO_AUTH=1 (an env-file typo, a copied base config)
		// cannot silently serve the whole dashboard, including every admin
		// mutation, with no authentication.
		log.Error("serve: SECURITY: insecure-no-auth is ACTIVE (--insecure-no-auth or REACTOR_INSECURE_NO_AUTH=1). The dashboard is served with NO authentication and all admin mutations are reachable unauthenticated. Use this ONLY in a trusted local/dev context; unset it for any shared or production deploy.")
	}
	// Bridge the legacy env-var BasicAuth into the users table: when creds are
	// configured and no matching user exists yet, seed them as the first admin.
	// SessionAuth then resolves a BasicAuth request to that admin (a "signed-in"
	// identity), which is what the session-gated write/build routes require
	// (upload, codegen, triggers). Without this a basic-auth-only deploy can
	// authenticate but never reach the dashboard's create surfaces. Idempotent.
	if srv.BasicAuth.User != "" && srv.BasicAuth.PasswordSHA256 != "" {
		if created, err := deps.authStore.EnsureAdminWithPHC(context.Background(), srv.BasicAuth.User, srv.BasicAuth.PasswordSHA256); err != nil {
			log.Warn("serve: could not seed admin user from BasicAuth env", "err", err)
		} else if created {
			log.Info("serve: seeded admin user from REACTOR_BASIC_AUTH_* so dashboard write/build routes are reachable", "user", srv.BasicAuth.User)
		}
	}
	return srv
}

// readContainerMemoryMax returns the daemon's own cgroup v2 memory.max
// (the container memory limit) as a string of bytes, "max" when unlimited,
// or "" when it can't be read (non-cgroup-v2 host, file absent). Used by the
// memory self-check to report the actual outer fence instead of guessing.
func readContainerMemoryMax() string {
	b, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// runServeLoop starts every long-running goroutine, waits for SIGINT/
// SIGTERM, and drains in-flight runs before returning. The shutdown
// order matters: stop trigger sources first so no new runs land, then
// drain the dispatcher, then wait for the goroutines.
func runServeLoop(ctx context.Context, log *slog.Logger, cfg *serveConfig, deps *serveDeps, srv *server.Server) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var runtimeReady atomic.Bool
	// The HTTP server is constructed before the component goroutines start.
	// Expose one shared flag to /readyz so a component failure withdraws
	// readiness across every request without coupling the server package to the
	// daemon's goroutine lifecycle.
	// An older database may contain active command schedules, webhooks, or
	// terminal chains even when this process was restarted with the command
	// runner disabled. Keep /readyz fail-closed in that state: the HTTP/MCP
	// control plane remains inspectable, but advertising readiness would let a
	// load balancer route durable automation work into a daemon that cannot
	// service those triggers. The query is tenant-scoped and existence-only, so
	// it does not load command text or trigger payloads.
	srv.RuntimeReady = func() bool {
		// A shutdown signal cancels runCtx before the component goroutines have
		// drained. Withdraw readiness immediately so an orchestrator cannot send
		// new MCP or trigger traffic into a daemon that is already stopping.
		if runCtx.Err() != nil {
			return false
		}
		if !runtimeReady.Load() {
			return false
		}
		return commandAutomationRuntimeReady(deps.journal, cfg.mcpTenant, cfg.commandRunnerEnabled)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		log.Info("serve: signal received, shutting down", "signal", s.String())
		cancel()
	}()

	var wg sync.WaitGroup
	// An essential component failure must make the daemon fail closed. A dead
	// HTTP listener, scheduler, cron driver, or rotation loop must not leave a
	// process that advertises ready while automations silently stop firing.
	// Keep the first failure for the caller after bounded shutdown/drain.
	componentErrCh := make(chan error, 1)
	// 0 = starting, 1 = ready, 2 = failed. The CAS prevents a late leader
	// startup callback from re-advertising readiness after another component
	// has already failed and cancelled the serve context.
	var readinessState atomic.Uint32
	reportComponentFailure := func(err error) {
		if err == nil {
			return
		}
		readinessState.Store(2)
		runtimeReady.Store(false)
		select {
		case componentErrCh <- err:
		default:
			// Another component already reported the failure that is shutting us
			// down. Never block a component goroutine during wg.Wait.
		}
		cancel()
	}
	// Keep readiness false until the queue (when configured) has started and
	// the leader goroutine has reached its startup fence. Previously this was
	// set before cron/scheduler/rotation startup, so /readyz could briefly
	// advertise a daemon that accepted MCP work while its trigger loops were
	// still starting (or about to fail on a malformed trigger). A component
	// failure still withdraws readiness through reportComponentFailure.
	deps.leaderReady = func() {
		if runCtx.Err() != nil {
			return
		}
		if readinessState.CompareAndSwap(0, 1) {
			runtimeReady.Store(true)
			log.Info("serve: ready",
				"addr", cfg.addr, "root", cfg.root,
				"scheduler_tick", cfg.tickInterval.String(),
				"rotation_tick", cfg.rotationInterval.String(),
				"cron_reload", cfg.cronReload.String())
		}
	}
	if deps.commandQueue != nil {
		// Keep command workers on an independent lifecycle context so the
		// shutdown path can stop intake, let active commands drain within
		// --drain-timeout, and only then cancel unfinished claims. Queue.Stop
		// remains the owner of this context; a runCtx cancellation reaches it
		// synchronously below rather than pre-empting the drain window here.
		if err := deps.commandQueue.Start(context.WithoutCancel(runCtx)); err != nil {
			reportComponentFailure(fmt.Errorf("command_runner_queue: %w", err))
		}
	}
	wg.Add(5)
	// HTTP + enqueue + cancel + retention run on EVERY instance.
	go func() {
		defer wg.Done()
		runCancelWatcher(runCtx, log, deps)
	}()
	go func() {
		defer wg.Done()
		runRetentionLoop(runCtx, log, deps)
	}()
	go func() {
		defer wg.Done()
		runCommandLeaseLoop(runCtx, log, deps)
	}()
	go func() {
		defer wg.Done()
		if err := runDaemonComponent(log, "http_server", func() error {
			return srv.RunWithTLS(runCtx, cfg.addr, server.TLSConfig{CertFile: cfg.tlsCert, KeyFile: cfg.tlsKey})
		}); err != nil {
			reportComponentFailure(fmt.Errorf("http_server: %w", err))
		}
	}()
	// Scheduler + cron + rotation are single-leader: in distributed mode an
	// advisory lock elects one instance to run them so resumes/crons/
	// rotations don't fire on every daemon. In local mode this instance is
	// the leader immediately.
	go func() {
		defer wg.Done()
		if err := runLeaderTasks(runCtx, log, cfg, deps); err != nil {
			reportComponentFailure(fmt.Errorf("leader_tasks: %w", err))
		}
	}()

	// Memory-enforcement self-check. RLIMIT_AS can't bound a Go heap (it
	// crashes the child at startup), so per-workflow memory is capped ONLY by
	// cgroup v2 memory.max (needs --cgroup-root + delegation). When that's
	// off, the fence is the daemon's own container memory limit. Report the
	// actual state: WARN loudly only if memory is truly unbounded, else note
	// the container limit that bounds it.
	if runtime.GOOS == "linux" && cfg.cgroupRoot == "" {
		switch limit := readContainerMemoryMax(); {
		case limit == "" || limit == "max":
			log.Warn("serve: workflow memory is UNBOUNDED (no --cgroup-root AND no container memory limit); a runaway workflow can exhaust the host. Set a container memory limit (e.g. docker --memory) or --cgroup-root=/sys/fs/cgroup with cgroup v2 delegation for per-workflow memory.max.")
		default:
			log.Info("serve: per-workflow memory limiting is off; total memory is bounded by the container limit", "container_memory_max_bytes", limit,
				"hint", "for per-workflow caps, set --cgroup-root=/sys/fs/cgroup with cgroup v2 delegation")
		}
	}

	<-runCtx.Done()
	runtimeReady.Store(false)
	if deps.commandQueue != nil {
		queueStopTimeout := cfg.drainTimeout
		if queueStopTimeout <= 0 {
			queueStopTimeout = 30 * time.Second
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), queueStopTimeout)
		if err := deps.commandQueue.Stop(stopCtx); err != nil {
			log.Warn("serve: command runner queue did not stop cleanly", "err", err)
		}
		stopCancel()
	}
	// Close scheduler admission before observing counts. Stop is idempotent and
	// runLeaderTasks also invokes it; the mutex gate makes this serialize with a
	// dispatch whose context check passed just before shutdown.
	deps.scheduler.Stop()
	deps.dispatcher.Stop()
	// Sample scheduler first: its terminal hook hands off to dispatcher before
	// decrementing its own count. Once scheduler is zero, the subsequent
	// dispatcher sample sees every child admitted by that handoff.
	scheduled, dispatched := deps.scheduler.InFlight(), deps.dispatcher.InFlight()
	if dispatched+scheduled > 0 {
		log.Info("serve: draining in-flight runs",
			"dispatcher_count", dispatched, "scheduler_count", scheduled,
			"timeout", cfg.drainTimeout.String())
		if err := drainServeExecutions(deps, cfg.drainTimeout); err != nil {
			// Drain timed out: kill the remaining subprocesses so they
			// don't orphan and so they stop touching the DB we are about
			// to close (deps.db.Close runs after this returns). Then give
			// them a short bounded window to persist a recoverable
			// infrastructure stop.
			admissions := deps.dispatcher.CancelAdmissions(cancelreg.ErrInfrastructureShutdown)
			killed := deps.cancels.CancelAllWithCause(cancelreg.ErrInfrastructureShutdown)
			log.Warn("serve: drain timed out; interrupted in-flight runs", "killed", killed, "admissions", admissions, "err", err)
			if killed+admissions > 0 {
				_ = drainServeExecutions(deps, 5*time.Second)
			}
		} else {
			log.Info("serve: drain complete")
		}
	}
	wg.Wait()
	log.Info("serve: shutdown complete")
	select {
	case err := <-componentErrCh:
		return fmt.Errorf("serve: %w", err)
	default:
		return nil
	}
}

// commandAutomationRuntimeReady projects the one runtime dependency that is
// not represented by the serve-loop component flags. Command automation
// schedules, webhooks, and terminal chains are durable rows; after a restart
// the operator may have disabled the runner while those rows remain active.
// In that case readiness must be withdrawn until the runner is restored or the
// rows are explicitly disabled. Ordinary command failures with a live runner
// remain per-trigger receipts and do not make the whole daemon unready.
func commandAutomationRuntimeReady(j *journal.Journal, tenantID string, runnerEnabled bool) bool {
	if runnerEnabled {
		return true
	}
	if j == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	active, err := j.HasActiveCommandAutomationTriggerForTenant(ctx, tenantID)
	return err == nil && !active
}

// drainServeExecutions waits on both entry paths that can own a workflow
// subprocess. Scheduler admission must be closed before calling it; otherwise a
// zero observation could race a due dispatch entering immediately afterward.
func drainServeExecutions(deps *serveDeps, timeout time.Duration) error {
	started := time.Now()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		scheduled, dispatched := deps.scheduler.InFlight(), deps.dispatcher.InFlight()
		if dispatched+scheduled == 0 {
			return nil
		}
		if timeout > 0 && time.Since(started) >= timeout {
			return fmt.Errorf("serve: drain timed out after %s with dispatcher=%d scheduler=%d in flight",
				timeout, dispatched, scheduled)
		}
		<-ticker.C
	}
}

// runAutoscaler builds + runs the worker autoscaler. The substrate is chosen
// with REACTOR_AUTOSCALE_SPAWNER (process|docker|kubernetes|command); see
// buildSpawner. Bounded by REACTOR_AUTOSCALE_MAX.
func runAutoscaler(ctx context.Context, log *slog.Logger, cfg *serveConfig, deps *serveDeps) {
	spawner, err := buildSpawner(log, cfg)
	if err != nil {
		log.Error("serve: autoscaler disabled", "err", err)
		return
	}
	ctrl := autoscale.New(cfg.autoscaleConfig, spawner, deps.journal, log)
	ctrl.Run(ctx)
}

// buildSpawner selects the autoscaler substrate from REACTOR_AUTOSCALE_SPAWNER:
//
//	process     (default) re-exec this binary as `reactor worker` on THIS host.
//	docker      `docker run` a worker container   (needs REACTOR_WORKER_IMAGE).
//	kubernetes  `kubectl create` a worker Job      (needs REACTOR_WORKER_IMAGE).
//	command     run operator shell commands (REACTOR_AUTOSCALE_SPAWN_CMD/_STOP_CMD).
//
// Everything except `process` is dependency-free: Reactor shells out to the
// operator's own docker/kubectl/whatever CLI rather than linking the Docker or
// Kubernetes SDKs, so one mechanism covers every orchestrator and pins no
// client version. process is the default because it needs zero external setup.
func buildSpawner(log *slog.Logger, cfg *serveConfig) (autoscale.Spawner, error) {
	if cfg == nil || len(cfg.masterKey) != 32 {
		return nil, errors.New("autoscaler needs the server's loaded 32-byte vault master key")
	}
	substrate := strings.ToLower(strings.TrimSpace(envFirstOr("process", "REACTOR_AUTOSCALE_SPAWNER")))
	concurrency := ""
	if substrate == "process" || substrate == "docker" {
		value, err := parseAutoscaleWorkerConcurrency()
		if err != nil {
			return nil, err
		}
		concurrency = strconv.Itoa(value)
	}
	switch substrate {
	case "process":
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("process spawner: cannot find own binary: %w", err)
		}
		args := []string{"worker", "--root", cfg.root, "--concurrency", concurrency}
		if cfg.queueArtifactRoot != "" {
			args = append(args, "--artifact-root", cfg.queueArtifactRoot)
		}
		log.Info("serve: autoscaler substrate = process (same-host child processes)")
		return autoscale.NewProcessSpawner(self, args, workerRuntimeEnv(cfg.dbURL, cfg.masterKey), log), nil

	case "docker":
		image := os.Getenv("REACTOR_WORKER_IMAGE")
		if image == "" {
			return nil, fmt.Errorf("docker spawner needs REACTOR_WORKER_IMAGE")
		}
		workerDrain := cfg.drainTimeout
		if workerDrain <= 0 {
			workerDrain = 30 * time.Second
		}
		if workerDrain > time.Duration(1<<63-1)-10*time.Second {
			return nil, fmt.Errorf("docker spawner drain timeout is too large")
		}
		// docker stop sends the container's stop signal and waits before a
		// final SIGKILL. Give the worker its full drain timeout plus room to
		// persist lease recovery; the CLI timeout must exceed Docker's grace.
		grace := workerDrain + 5*time.Second
		graceSeconds := int64(grace / time.Second)
		if grace%time.Second != 0 {
			graceSeconds++
		}
		spawn := []string{"docker", "run", "-d", "--rm", "--label", "reactor-worker=1"}
		spawn = append(spawn, strings.Fields(os.Getenv("REACTOR_AUTOSCALE_DOCKER_ARGS"))...)
		spawn = append(spawn, "--env", "REACTOR_DB_URL", "--env", "REACTOR_MASTER_KEY")
		spawn = append(spawn, image, "worker", "--root", cfg.root, "--concurrency", concurrency)
		if cfg.queueArtifactRoot != "" {
			spawn = append(spawn, "--artifact-root", cfg.queueArtifactRoot)
		}
		spawn = append(spawn, "--drain-timeout", workerDrain.String())
		// `--rm` removes the container after the graceful stop finishes.
		// A separate terminal-state cleanup uses non-forced `docker rm`.
		stop := []string{"docker", "stop", "--signal", "SIGTERM", "--time", strconv.FormatInt(graceSeconds, 10), "{id}"}
		log.Info("serve: autoscaler substrate = docker", "image", image)
		sp := autoscale.NewCommandSpawner(spawn, stop, workerRuntimeEnv(cfg.dbURL, cfg.masterKey), log)
		sp.StopTimeout = workerDrain + 10*time.Second
		return sp, nil

	case "kubernetes", "k8s":
		image := os.Getenv("REACTOR_WORKER_IMAGE")
		if image == "" {
			return nil, fmt.Errorf("kubernetes spawner needs REACTOR_WORKER_IMAGE")
		}
		if strings.TrimSpace(os.Getenv("REACTOR_AUTOSCALE_K8S_DB_SECRET")) == "" {
			return nil, fmt.Errorf("kubernetes spawner needs REACTOR_AUTOSCALE_K8S_DB_SECRET")
		}
		if strings.TrimSpace(os.Getenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET")) == "" {
			return nil, fmt.Errorf("kubernetes spawner needs REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET")
		}
		artifactPVC, artifactRoot, err := kubernetesArtifactMountConfig(cfg.root)
		if err != nil {
			return nil, err
		}
		resources, err := parseKubernetesWorkerResources()
		if err != nil {
			return nil, err
		}
		concurrency = strconv.FormatInt(resources.concurrency, 10)
		workerDrain := cfg.drainTimeout
		if workerDrain <= 0 {
			workerDrain = 30 * time.Second
		}
		if workerDrain > time.Duration(1<<63-1)-15*time.Second {
			return nil, fmt.Errorf("kubernetes spawner drain timeout is too large")
		}
		// Job deletion sends SIGTERM to the Pod. Give the worker its full
		// drain window plus room to persist an interrupted lease. Round the
		// Pod grace upward because Kubernetes expresses it in whole seconds.
		grace := workerDrain + 10*time.Second
		graceSeconds := int64(grace / time.Second)
		if grace%time.Second != 0 {
			graceSeconds++
		}
		ns := envFirstOr("default", "REACTOR_AUTOSCALE_K8S_NAMESPACE")
		spawn := []string{"kubectl", "create", "--namespace", ns, "-f", "-", "-o", "name"}
		// A background Job deletion can remove the inventory handle while its
		// Pod is still draining. Keep the Job (and the autoscaler capacity slot)
		// until Kubernetes has removed the dependent Pod.
		stop := []string{"kubectl", "delete", "--namespace", ns, "--ignore-not-found", "--cascade=foreground", "--wait=true", "{id}"}
		sp := autoscale.NewCommandSpawner(spawn, stop, os.Environ(), log)
		sp.SpawnStdin = []byte(k8sWorkerJobManifest(image, ns, cfg, concurrency, artifactPVC, artifactRoot, resources, workerDrain, graceSeconds))
		sp.StopTimeout = workerDrain + 15*time.Second
		log.Info("serve: autoscaler substrate = kubernetes", "image", image, "namespace", ns)
		return sp, nil

	case "command":
		spawnCmd := os.Getenv("REACTOR_AUTOSCALE_SPAWN_CMD")
		if spawnCmd == "" {
			return nil, fmt.Errorf("command spawner needs REACTOR_AUTOSCALE_SPAWN_CMD")
		}
		spawn := []string{"sh", "-c", spawnCmd}
		var stop []string
		if stopCmd := os.Getenv("REACTOR_AUTOSCALE_STOP_CMD"); stopCmd != "" {
			stop = []string{"sh", "-c", stopCmd}
		}
		log.Info("serve: autoscaler substrate = command (operator-supplied)")
		return autoscale.NewCommandSpawner(spawn, stop, os.Environ(), log), nil

	default:
		return nil, fmt.Errorf("unknown REACTOR_AUTOSCALE_SPAWNER %q (want process|docker|kubernetes|command)", substrate)
	}
}

// workerRuntimeEnv gives local and Docker workers the configured DB URL and
// loaded vault key through their environment, keeping both out of process
// argv and Docker Cmd metadata. Remove inherited values so workers use the
// server's active configuration even when it came from flags or a key file.
func workerRuntimeEnv(dbURL string, masterKey []byte) []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+2)
	for _, entry := range env {
		if !strings.HasPrefix(entry, "REACTOR_DB_URL=") && !strings.HasPrefix(entry, "REACTOR_MASTER_KEY=") &&
			!strings.HasPrefix(entry, workerParentFDEnv+"=") {
			out = append(out, entry)
		}
	}
	return append(out, "REACTOR_DB_URL="+dbURL, "REACTOR_MASTER_KEY="+hex.EncodeToString(masterKey))
}

// k8sWorkerJobManifest builds the Job YAML piped to `kubectl create -f -`.
// generateName makes each Job unique; ttlSecondsAfterFinished garbage-collects
// finished Jobs. The DB URL and vault master key are read from required
// Kubernetes Secrets into worker environment variables. Neither value appears
// in the Job manifest or worker arguments.
func k8sWorkerJobManifest(image, ns string, cfg *serveConfig, concurrency, artifactPVC, artifactRoot string, resources kubernetesWorkerResources, workerDrain time.Duration, graceSeconds int64) string {
	dbSecret := os.Getenv("REACTOR_AUTOSCALE_K8S_DB_SECRET")
	dbKey := envFirstOr("db-url", "REACTOR_AUTOSCALE_K8S_DB_SECRET_KEY")
	masterSecret := os.Getenv("REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET")
	masterKey := envFirstOr("master-key", "REACTOR_AUTOSCALE_K8S_MASTER_KEY_SECRET_KEY")
	return fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  generateName: reactor-worker-
  namespace: %q
  labels:
    app: reactor-worker
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 120
  template:
    metadata:
      labels:
        app: reactor-worker
    spec:
      restartPolicy: Never
      terminationGracePeriodSeconds: %d
      containers:
        - name: worker
          image: %q
          env:
            - name: REACTOR_DB_URL
              valueFrom:
                secretKeyRef:
                  name: %q
                  key: %q
            - name: REACTOR_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: %q
                  key: %q
            - name: REACTOR_WORKER_ARTIFACT_ROOT
              value: %q
          resources:
            requests:
              cpu: %q
              memory: %q
            limits:
              cpu: %q
              memory: %q
          volumeMounts:
            - name: workflow-artifacts
              mountPath: %q
              readOnly: true
          args: ["worker", "--root", %q, "--concurrency", %q, "--drain-timeout", %q]
      volumes:
        - name: workflow-artifacts
          persistentVolumeClaim:
            claimName: %q
            readOnly: true
`, ns, graceSeconds, image, dbSecret, dbKey, masterSecret, masterKey,
		artifactRoot,
		strconv.FormatInt(resources.cpuRequestMilli, 10)+"m", strconv.FormatInt(resources.memoryRequestMiB, 10)+"Mi",
		strconv.FormatInt(resources.cpuLimitMilli, 10)+"m", strconv.FormatInt(resources.memoryLimitMiB, 10)+"Mi",
		artifactRoot, cfg.root, concurrency, workerDrain.String(), artifactPVC)
}

// leaderLockKey is the fixed Postgres advisory-lock key that elects the
// single instance allowed to run the scheduler + cron + rotation in
// distributed mode. Arbitrary but stable across the fleet.
const leaderLockKey = 0x4152414348 // "ARACH"

// runLeaderTasks runs the single-leader background loops (scheduler, cron
// driver, rotation runner, and distributed lease recovery). An unexpected exit is returned to runServeLoop,
// which stops the daemon so its ready listener cannot outlive automation
// dispatch. In distributed mode it first blocks on a
// Postgres advisory lock so only one serve instance runs them; followers
// wait here and take over if the leader dies (the lock auto-releases when
// the holding connection drops). In local mode it is leader immediately.
func runLeaderTasks(ctx context.Context, log *slog.Logger, cfg *serveConfig, deps *serveDeps) error {
	if cfg.distributed() {
		conn, err := deps.db.Conn(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("leadership connection: %w", err)
		}
		defer conn.Close()
		// A distributed follower is still able to serve HTTP/MCP and enqueue
		// workflow work while another replica owns the scheduler/cron/rotation
		// lock. Signal readiness after the database connection is established,
		// before waiting on the advisory lock.
		if deps.leaderReady != nil {
			deps.leaderReady()
		}
		log.Info("serve: waiting for scheduler/cron leadership (advisory lock)")
		// Blocking acquire. Respects ctx: on shutdown the driver cancels
		// the waiting query so a follower exits cleanly.
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", leaderLockKey); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("acquire leadership: %w", err)
		}
		defer func() {
			_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", leaderLockKey)
		}()
		log.Info("serve: acquired scheduler/cron leadership")
	}

	leaderCtx, cancelLeader := context.WithCancel(ctx)
	defer cancelLeader()
	// Recover expired worker claims before this leader advertises readiness or
	// starts autoscaling. Worker-owned reapers cannot make progress when the
	// entire worker fleet has exited and autoscale min is zero: such runs remain
	// "running", so the queue-depth signal alone would never start a replacement.
	var leaseBacklog bool
	if cfg.distributed() {
		var err error
		leaseBacklog, err = drainExpiredRunLeases(leaderCtx, log, deps.journal, expiredRunLeaseExists(deps.db))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("initial distributed lease recovery: %w", err)
		}
	}
	if err := deps.cronDriver.Start(leaderCtx); err != nil {
		deps.cronDriver.Stop()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("start cron driver: %w", err)
	}
	if deps.commandScheduleDriver != nil {
		if err := deps.commandScheduleDriver.Start(leaderCtx); err != nil {
			deps.commandScheduleDriver.Stop()
			deps.cronDriver.Stop()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("start command schedule driver: %w", err)
		}
	}
	if deps.rotRunner == nil {
		deps.cronDriver.Stop()
		if deps.commandScheduleDriver != nil {
			deps.commandScheduleDriver.Stop()
		}
		return errors.New("rotation runner is not configured")
	}
	// Initialize before launching the goroutine. Runner.Stop is part of the
	// shutdown path and must see a stable stop channel even if the process is
	// cancelled immediately after startup.
	deps.rotRunner.Initialize()
	componentErrCh := make(chan error, 1)
	report := func(err error) {
		if err == nil {
			return
		}
		select {
		case componentErrCh <- err:
		default:
		}
		cancelLeader()
	}
	var lwg sync.WaitGroup
	lwg.Add(3)
	go func() {
		defer lwg.Done()
		report(runLeaderComponent(leaderCtx, log, "scheduler", func() error { return deps.scheduler.Run(leaderCtx) }))
	}()
	go func() {
		defer lwg.Done()
		report(runLeaderComponent(leaderCtx, log, "rotation_runner", func() error { return deps.rotRunner.Run(leaderCtx) }))
	}()
	go func() {
		defer lwg.Done()
		runTerminalEffectLoop(leaderCtx, log, deps)
	}()
	if cfg.distributed() {
		lwg.Add(1)
		go func() {
			defer lwg.Done()
			report(runLeaderComponent(leaderCtx, log, "lease_reaper", func() error {
				return runLeaderLeaseReaper(leaderCtx, log, deps.journal, expiredRunLeaseExists(deps.db), leaseBacklog)
			}))
		}()
	}
	// Local mode reaches this point only after every trigger source has loaded
	// and all long-running leader loops have been launched. In distributed mode
	// this is also harmless: the follower was already marked ready while it
	// waited for the advisory lock, and the callback is idempotent.
	if deps.leaderReady != nil {
		deps.leaderReady()
	}
	// Worker autoscaler: leader-only, distributed-mode-only, opt-in. Spawns
	// + stops `reactor worker` processes to track queue depth.
	if cfg.distributed() && cfg.autoscale {
		lwg.Add(1)
		go func() {
			defer lwg.Done()
			runAutoscaler(leaderCtx, log, cfg, deps)
		}()
	}
	select {
	case <-ctx.Done():
	case <-leaderCtx.Done():
	}
	cancelLeader()
	if deps.commandScheduleDriver != nil {
		deps.commandScheduleDriver.Stop()
	}
	deps.cronDriver.Stop()
	deps.scheduler.Stop()
	deps.rotRunner.Stop()
	lwg.Wait()
	select {
	case err := <-componentErrCh:
		return err
	default:
		return nil
	}
}

// runLeaderComponent treats a clean early exit as a failure too. A component
// that silently returned nil before shutdown is no longer running the
// scheduler or rotation loop and must not leave the daemon advertising ready.
func runLeaderComponent(ctx context.Context, log *slog.Logger, name string, fn func() error) error {
	err := runDaemonComponent(log, name, fn)
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return fmt.Errorf("%s: exited before shutdown", name)
}

// Adapter types live in adapters.go (editValidator, generatorAdapter,
// knowledgeAdapter, workflowRegistrarAdapter). See that file for the
// thin shims that bridge codegen + knowledge + registry packages onto
// the server.* interfaces.

// envFirst reads the first non-empty value from the provided env vars.
// Used to migrate from the legacy ARACHNE_* prefix to REACTOR_* without
// breaking running deployments: callers pass the canonical key first
// and the deprecated key second. Logs a one-time deprecation warning
// when the legacy key resolves the value.
// buildMFAOptions assembles the auth.Store MFA options. TOTP encryption key is
// derived from the daemon master key (so no new required secret; TOTP is simply
// unavailable when the master key is unset). WebAuthn passkeys need the relying
// party domain: taken from REACTOR_WEBAUTHN_RP_ID / _RP_ORIGIN, else derived
// from REACTOR_DASHBOARD_URL. When neither yields a domain, passkeys stay off
// and the /security page says so.
func buildMFAOptions(log *slog.Logger, masterKey []byte) []auth.Option {
	var opts []auth.Option
	if key := auth.DeriveMFAKey(masterKey); key != nil {
		opts = append(opts, auth.WithMFAKey(key))
	} else {
		log.Info("serve: TOTP disabled (no master key set; passkeys still work)")
	}
	rpOrigin := envFirst("REACTOR_WEBAUTHN_RP_ORIGIN")
	if rpOrigin == "" {
		rpOrigin = envFirst("REACTOR_DASHBOARD_URL")
	}
	rpID := envFirst("REACTOR_WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = auth.RPIDFromOrigin(rpOrigin)
	}
	if rpID == "" || rpOrigin == "" {
		log.Info("serve: WebAuthn passkeys disabled (set REACTOR_WEBAUTHN_RP_ID + REACTOR_WEBAUTHN_RP_ORIGIN, or REACTOR_DASHBOARD_URL)")
		return opts
	}
	wa, err := auth.NewWebAuthn(rpID, "Reactor", []string{rpOrigin})
	if err != nil {
		log.Warn("serve: WebAuthn passkeys disabled (invalid config)", "err", err)
		return opts
	}
	opts = append(opts, auth.WithWebAuthn(wa))
	log.Info("serve: WebAuthn passkeys enabled", "rp_id", rpID, "rp_origin", rpOrigin)
	return opts
}

func envFirst(keys ...string) string {
	for i, k := range keys {
		if v := os.Getenv(k); v != "" {
			if i > 0 {
				warnDeprecatedEnv(k, keys[0])
			}
			return v
		}
	}
	return ""
}

func envIntFirst(canonical, legacy string, def int) int {
	if v := envFirst(canonical, legacy); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDurationFirst(canonical, legacy string, def time.Duration) time.Duration {
	if v := envFirst(canonical, legacy); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envFloatFirst(canonical, legacy string, def float64) float64 {
	if v := envFirst(canonical, legacy); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

var deprecatedEnvOnce sync.Map

func warnDeprecatedEnv(legacy, canonical string) {
	if _, loaded := deprecatedEnvOnce.LoadOrStore(legacy, true); loaded {
		return
	}
	fmt.Fprintf(os.Stderr, "reactor: %s is deprecated; rename to %s before v0.3\n", legacy, canonical)
}

// envInt reads an env var as int, falling back to def when missing or
// unparseable. Used for the rate-limit knobs so operators can tune
// without changing flag names.
func envInt(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// envFloat reads an env var as float64 with a fallback.
func envFloat(key string, def float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return f
}

// loadMasterKey resolves the master key from (in order): explicit
// --master-key flag, --master-key-file flag, ARACHNE_MASTER_KEY env, then
// <root>/master.key. Returns the hex string with whitespace trimmed.
func loadMasterKey(hexFlag, file, root string) (string, error) {
	if hexFlag != "" {
		return strings.TrimSpace(hexFlag), nil
	}
	candidate := file
	if candidate == "" {
		candidate = filepath.Join(root, "master.key")
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", fmt.Errorf("serve: inspect master key %s: %w", candidate, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("serve: master key %s must be a regular file, not a symlink or special file", candidate)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("serve: master key %s is readable by group or other (mode %04o); chmod 0600", candidate, info.Mode().Perm())
	}
	data, err := os.ReadFile(candidate)
	if err != nil {
		return "", fmt.Errorf("serve: read master key %s: %w (run `reactor init` first?)", candidate, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// validatePrivateStateRoot enforces the filesystem boundary assumed by the
// workflow supervisor: the daemon's state contains the vault key and
// immutable workflow artifacts, so a shared or symlinked root would let an
// unrelated local account read or replace execution material.
func validatePrivateStateRoot(root string) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("root is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("root must be a real directory, not a symlink or file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("root is readable by group or other (mode %04o); chmod 0700", info.Mode().Perm())
	}
	return nil
}

// runDaemonComponent invokes fn under a deferred panic recovery so a single
// crash in a long-running daemon goroutine (scheduler, rotation_runner,
// http_server) cannot silently kill that subsystem without a log line. The
// runtime context cancellation is the normal shutdown path; a panic is the
// pathological one we want to surface. Mirrors the dockyard + mithras
// runWorker pattern shipped 2026-05-21. Non-Canceled errors are still
// logged at Error so an unexpected exit is visible without grepping.
func runDaemonComponent(log *slog.Logger, name string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("serve: component panicked",
				"component", name,
				"panic", r,
				"stack", string(debug.Stack()),
			)
			err = fmt.Errorf("component %s panicked: %v", name, r)
		}
	}()
	if err := fn(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		log.Error("serve: component exited", "component", name, "err", err)
		return err
	}
	return nil
}

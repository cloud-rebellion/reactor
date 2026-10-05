package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bright-interaction/reactor/internal/registry"
	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

func TestCreateMCPPinnedRunPersistsExactArtifact(t *testing.T) {
	_, j := newSeededDB(t)
	ctx := context.Background()
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	if err := reg.ClaimTenant("demo", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(source, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("demo", source)
	if err != nil {
		t.Fatal(err)
	}
	version, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_t", "0.1.0", "h2", artifact.Digest, json.RawMessage(`{"version":2}`))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := createMCPPinnedRun(ctx, j, reg, "run_mcp_pinned", "wf_t", "demo", json.RawMessage(`{"source":"mcp"}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if binary != artifact.Path {
		t.Fatalf("binary = %q, want immutable %q", binary, artifact.Path)
	}
	run, err := j.GetRun(ctx, "run_mcp_pinned")
	if err != nil {
		t.Fatal(err)
	}
	if run.WorkflowVersion != version || run.WorkflowArtifactSHA256 != artifact.Digest {
		t.Fatalf("MCP run pins = version %d digest %q", run.WorkflowVersion, run.WorkflowArtifactSHA256)
	}
}

func TestMetadataOnlyMCPWorkflowFailsClosedWithoutRun(t *testing.T) {
	_, j := newSeededDB(t) // wf_t is deliberately metadata-only.
	ctx := context.Background()
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	if _, err := createMCPPinnedRun(ctx, j, reg, "run_metadata_only", "wf_t", "demo", nil, false); !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("metadata-only workflow dispatch = %v, want artifact fence", err)
	}
	if _, err := j.GetRun(ctx, "run_metadata_only"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("metadata-only workflow created executable run: %v", err)
	}
}

func TestCreateMCPPinnedRunRejectsTamperedOrMissingArtifactWithoutRow(t *testing.T) {
	_, j := newSeededDB(t)
	ctx := context.Background()
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	if err := reg.ClaimTenant("demo", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(source, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("demo", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_t", "0.1.0", "h2", artifact.Digest, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact.Path, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := createMCPPinnedRun(ctx, j, reg, "run_mcp_tampered", "wf_t", "demo", nil, false); !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("tampered MCP artifact = %v, want fence", err)
	}
	if _, err := j.GetRun(ctx, "run_mcp_tampered"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("tampered MCP dispatch created a run: %v", err)
	}

	missing := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_t", "0.1.0", "h3", missing, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := createMCPPinnedRun(ctx, j, reg, "run_mcp_missing", "wf_t", "demo", nil, false); !errors.Is(err, journal.ErrWorkflowArtifactFence) {
		t.Fatalf("missing MCP artifact = %v, want fence", err)
	}
	if _, err := j.GetRun(ctx, "run_mcp_missing"); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("missing MCP dispatch created a run: %v", err)
	}
}

func TestCreateMCPQueuedPinnedRunForDistributedWorker(t *testing.T) {
	_, j := newSeededDB(t)
	ctx := context.Background()
	reg := registry.New(filepath.Join(t.TempDir(), "workflows"))
	if err := reg.ClaimTenant("demo", journal.DefaultTenant); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "workflow")
	if err := os.WriteFile(source, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	artifact, err := reg.PublishArtifact("demo", source)
	if err != nil {
		t.Fatal(err)
	}
	version, err := j.RecordWorkflowVersionWithArtifact(ctx, "wf_t", "0.1.0", "h2", artifact.Digest, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createMCPPinnedRun(ctx, j, reg, "run_mcp_queued", "wf_t", "demo", json.RawMessage(`{"source":"mcp"}`), true); err != nil {
		t.Fatal(err)
	}
	run, err := j.GetRun(ctx, "run_mcp_queued")
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "queued" || run.WorkflowVersion != version || run.WorkflowArtifactSHA256 != artifact.Digest {
		t.Fatalf("distributed MCP run = %+v", run)
	}
}

func TestMCPDispatchTopologyQueuesPostgresOnly(t *testing.T) {
	if !mcpDispatchUsesWorkerQueue(journal.EnginePostgres) {
		t.Fatal("PostgreSQL MCP dispatch would bypass the leased worker queue")
	}
	if mcpDispatchUsesWorkerQueue(journal.EngineSQLite) {
		t.Fatal("SQLite development dispatch unexpectedly selected a worker queue")
	}
}

func TestPrepareMCPDispatchUsesDefaultTenantWhenSlugExistsElsewhere(t *testing.T) {
	_, j := newSeededDB(t)
	ctx := context.Background()
	if err := j.UpsertTenant(ctx, journal.Tenant{TenantID: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := j.CreateWorkflowInTenant(ctx, "wf_other", "demo", "h", "0.1.0", json.RawMessage(`{}`), "other"); err != nil {
		t.Fatal(err)
	}
	wfID, _, _, err := prepareMCPDispatch(ctx, j, "demo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if wfID != "wf_t" {
		t.Fatalf("MCP resolved ambiguous slug to %q, want default-tenant wf_t", wfID)
	}
}

func TestPrepareMCPDispatchEnforcesAdmissionControls(t *testing.T) {
	t.Run("workflow disabled", func(t *testing.T) {
		_, j := newSeededDB(t)
		if err := j.SetWorkflowEnabled(context.Background(), "wf_t", false); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := prepareMCPDispatch(context.Background(), j, "demo", nil); err == nil {
			t.Fatal("disabled workflow was admitted")
		}
	})
	t.Run("tenant quota", func(t *testing.T) {
		_, j := newSeededDB(t)
		if err := j.UpsertTenant(context.Background(), journal.Tenant{TenantID: journal.DefaultTenant, Disabled: true}); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := prepareMCPDispatch(context.Background(), j, "demo", nil)
		var quota *journal.QuotaError
		if !errors.As(err, &quota) {
			t.Fatalf("tenant-disabled dispatch = %v, want QuotaError", err)
		}
	})
	t.Run("workflow rate", func(t *testing.T) {
		_, j := newSeededDB(t)
		if err := j.SetWorkflowRateLimit(context.Background(), "wf_t", 1); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := prepareMCPDispatch(context.Background(), j, "demo", nil); err == nil {
			t.Fatal("rate-limited workflow was admitted")
		}
	})
}

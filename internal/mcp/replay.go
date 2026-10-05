package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bright-interaction/reactor/internal/runtime/journal"
)

// registerReplayTool exposes deliberate, exact-input replay for a completed
// run. It is separate from reactor_dispatch_workflow so an AI cannot silently
// turn a diagnostic read into a new side effect. Replays require the same
// dispatch scope and the durable idempotent dispatcher used by manual runs.
func (s *Server) registerReplayTool() {
	if s.Journal == nil || s.Dispatch == nil || s.DispatchIdempotent == nil ||
		!s.writeEnabled(s.Scopes == nil || s.Scopes.Dispatch) {
		return
	}

	s.tools["reactor_replay_run"] = toolDef{
		tool: Tool{
			Name:        "reactor_replay_run",
			Description: "Replay one completed tenant run with the exact retained trigger bytes. The caller must confirm the recorded input_sha256 and provide a fresh idempotency_key; Reactor validates the payload as an untrusted JSON object, rechecks current workflow admission, and dispatches through the canonical manual path. Active runs, digest mismatches, foreign runs, legacy inputs that no longer match their fingerprint, and reused idempotency keys are refused.",
			InputSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"run_id", "input_sha256", "idempotency_key"},
				"properties": map[string]any{
					"run_id":          map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
					"input_sha256":    map[string]any{"type": "string", "minLength": 64, "maxLength": 64, "description": "Exact opaque fingerprint returned by reactor_get_run"},
					"idempotency_key": map[string]any{"type": "string", "minLength": 1, "maxLength": 200, "description": "Fresh key for this replay; keys already bound to a run are rejected"},
				},
			},
		},
		handler: func(ctx context.Context, args json.RawMessage) (any, error) {
			var a struct {
				RunID          string `json:"run_id"`
				InputSHA256    string `json:"input_sha256"`
				IdempotencyKey string `json:"idempotency_key"`
			}
			if err := decodeMCPArgs(args, &a); err != nil {
				return nil, err
			}
			a.RunID = strings.TrimSpace(a.RunID)
			if a.RunID == "" || len(a.RunID) > 256 {
				return nil, fmt.Errorf("%w: run_id is required and must be at most 256 characters", errInvalidParamsErr)
			}
			digest, err := replayDigest(a.InputSHA256)
			if err != nil {
				return nil, err
			}
			key, err := replayIdempotencyKey(a.IdempotencyKey)
			if err != nil {
				return nil, err
			}

			// Resolve by tenant before reading any other run property. A foreign
			// run is intentionally indistinguishable from an unknown id.
			info, err := s.Journal.GetRunForTenantInputBounded(ctx, a.RunID, s.tenantID(ctx), maxMCPDispatchPayloadBytes)
			if err != nil {
				if errors.Is(err, journal.ErrRunInputTooLarge) {
					return nil, fmt.Errorf("%w: run input is empty or exceeds the %d-byte replay limit", errInvalidParamsErr, maxMCPDispatchPayloadBytes)
				}
				return nil, err
			}
			switch info.Status {
			case "succeeded", "failed", "failed_dlq", "cancelled":
			default:
				return nil, fmt.Errorf("%w: run %q is not terminal and cannot be replayed", errInvalidParamsErr, a.RunID)
			}

			payload := info.ExecutionInput()
			if len(payload) == 0 || len(payload) > maxMCPDispatchPayloadBytes {
				return nil, fmt.Errorf("%w: run input is empty or exceeds the %d-byte replay limit", errInvalidParamsErr, maxMCPDispatchPayloadBytes)
			}
			computed := sha256.Sum256(payload)
			computedDigest := hex.EncodeToString(computed[:])
			if info.InputSHA256 == "" || info.InputSHA256 != digest || computedDigest != digest {
				return nil, fmt.Errorf("%w: input_sha256 does not match the retained run input", errInvalidParamsErr)
			}
			if err := validateReplayObjectPayload(payload); err != nil {
				return nil, err
			}

			slug, err := s.Journal.WorkflowSlugByID(ctx, info.WorkflowID)
			if err != nil {
				return nil, err
			}
			resolvedID, err := s.Journal.WorkflowIDBySlugInTenant(ctx, slug, s.tenantID(ctx))
			if err != nil {
				return nil, err
			}
			if resolvedID != info.WorkflowID {
				return nil, journal.ErrNotFound
			}

			// A replay must always create a fresh idempotency binding. Check the
			// durable key before admission so a caller cannot accidentally turn
			// this operation into a second read/retry of the source run. The
			// dispatcher remains the race-safe authority for concurrent callers.
			if existing, findErr := s.Journal.FindMCPDispatchRun(ctx, info.WorkflowID, key, digest); findErr == nil {
				return nil, fmt.Errorf("%w: idempotency_key is already bound to run %q", errInvalidParamsErr, existing)
			} else if errors.Is(findErr, journal.ErrMCPDispatchIdempotencyConflict) {
				return nil, fmt.Errorf("%w: idempotency_key is already bound to another payload", errInvalidParamsErr)
			} else if !errors.Is(findErr, journal.ErrNotFound) {
				return nil, findErr
			}

			admission, err := s.workflowDispatchPreflight(ctx, slug)
			if err != nil {
				return nil, err
			}
			ready, _ := admission["dispatchable_now"].(bool)
			if !ready {
				reason, _ := admission["reason"].(string)
				if reason == "" {
					reason = "workflow admission gates did not pass"
				}
				return nil, fmt.Errorf("%w: workflow is not dispatchable: %s", errInvalidParamsErr, reason)
			}

			runID, err := s.DispatchIdempotent(ctx, slug, json.RawMessage(payload), key)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(runID) == "" {
				return nil, errors.New("mcp: replay dispatcher returned an empty run id")
			}
			result := map[string]any{
				"run_id":                runID,
				"replayed_from_run_id":  info.ID,
				"slug":                  slug,
				"input_sha256":          digest,
				"input_source":          replayInputSource(info),
				"idempotency_key_bound": true,
			}
			if replayed, readErr := s.Journal.GetRunForTenantMetadata(ctx, runID, s.tenantID(ctx), 0); readErr == nil {
				result["run"] = mcpRunView(replayed)
			}
			return result, nil
		},
	}
}

func replayDigest(raw string) (string, error) {
	digest := strings.TrimSpace(raw)
	if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return "", fmt.Errorf("%w: input_sha256 must be a lowercase SHA-256 digest", errInvalidParamsErr)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("%w: input_sha256 must be a lowercase SHA-256 digest", errInvalidParamsErr)
	}
	return digest, nil
}

func replayIdempotencyKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" || len(key) > 200 || strings.IndexFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", fmt.Errorf("%w: idempotency_key must be a fresh 1..200 character value without control characters", errInvalidParamsErr)
	}
	return key, nil
}

// validateReplayObjectPayload checks the same untrusted input shape enforced
// by manual dispatch while preserving the original bytes for exact replay.
// normalizeMCPObjectPayload trims surrounding whitespace, which would change
// the recorded digest, so replay validates a trimmed view and returns no copy.
func validateReplayObjectPayload(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !json.Valid(trimmed) {
		return fmt.Errorf("%w: retained run input must be a valid JSON object", errInvalidParamsErr)
	}
	if duplicateJSONKey(trimmed) {
		return fmt.Errorf("%w: retained run input contains duplicate object keys", errInvalidParamsErr)
	}
	return nil
}

func replayInputSource(info journal.RunInfo) string {
	if info.TriggerInput != nil {
		return "trigger_input"
	}
	return "legacy_trigger_meta"
}

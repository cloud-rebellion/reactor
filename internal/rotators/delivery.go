package rotators

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/bright-interaction/reactor/internal/credentials"
	"github.com/bright-interaction/reactor/internal/safehttp"
	"github.com/bright-interaction/reactor/internal/vault"
)

// DeliveryHTTPClient is the shared client for rotation deliveries. It is
// SSRF-hardened (see internal/safehttp): it refuses redirects (a delivery
// target that 302s to http://169.254.169.254/ would otherwise POST the freshly
// rotated PLAINTEXT secret to the cloud-metadata endpoint) and blocks the
// metadata/link-local ranges at connect time. allowPrivate is true because
// rotation legitimately reloads INTERNAL services (the reload_endpoint
// targets); the always-blocked metadata range still can't be reached.
var DeliveryHTTPClient = safehttp.Client(true)

// DeliveryResult records the outcome of a single target delivery.
type DeliveryResult struct {
	Target  credentials.Target
	Success bool
	Status  int
	Error   string
}

// DeliveryPayload is what a webhook target receives. previous lets the
// consumer accept BOTH old and new during a grace window if it wants to
// implement zero-downtime rollover; consumers without grace just
// overwrite to value. Phase is set on reload_endpoint deliveries to
// "open" (deploy new + old) or "close" (clear previous, keep new only);
// empty for single-phase webhook deliveries.
type DeliveryPayload struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Previous string `json:"previous,omitempty"`
	Phase    string `json:"phase,omitempty"`
}

// Deliver dispatches a credential rotation to a single target. Two
// kinds are supported in v1:
//
//	webhook         single-phase HMAC-signed POST. Receiver atomically
//	                replaces the named key. Simplest contract; works
//	                for any service that exposes a /reload endpoint.
//
//	reload_endpoint dual-phase HMAC-signed POST with a configurable
//	                grace window between phases. The receiver accepts
//	                BOTH old and new during the grace so in-flight
//	                requests authenticated with the old key complete,
//	                then a second POST closes the grace by clearing
//	                the previous-value field. Zero-downtime rotation
//	                for services that have actively-authenticated
//	                sessions (BrightCRM <-> atomicsite, scanner-
//	                dashboard <-> svar-go, etc).
//
// Both kinds use the same signature scheme: HMAC-SHA256 over the raw
// body, hex-encoded, sent as `X-Reactor-Signature: sha256=<hex>`.
// Receivers verify constant-time before applying.
//
// Delivery payload shape (DeliveryPayload struct below) is the same
// for both kinds; the Phase field discriminates open/close for
// reload_endpoint targets and is empty for webhook.
func Deliver(ctx context.Context, target credentials.Target, oldValue, newValue string, vaultStore *vault.Store) DeliveryResult {
	res := DeliveryResult{Target: target}
	// Validate kind FIRST so an unknown kind reports the right error
	// regardless of which fields are filled. The kind dictates which
	// fields are required, so checking fields against an unknown kind
	// is meaningless.
	// One validator shared with the dashboard's target form
	// (credentials.Target.Validate), so the fields the UI demands and the fields
	// delivery requires cannot drift apart.
	if err := target.Validate(); err != nil {
		res.Error = err.Error()
		return res
	}
	switch target.Kind {
	case "webhook", "reload_endpoint":
		hmacSecret, err := vaultStore.Get(ctx, target.SecretID)
		if err != nil {
			res.Error = "vault: " + err.Error()
			return res
		}
		if target.Kind == "webhook" {
			return deliverWebhook(ctx, target, oldValue, newValue, hmacSecret.Reveal())
		}
		return deliverReloadEndpoint(ctx, target, oldValue, newValue, hmacSecret.Reveal())
	case "file_write":
		return deliverFileWrite(target, newValue)
	case "forgejo_secret":
		token, err := vaultStore.Get(ctx, target.SecretID)
		if err != nil {
			res.Error = "vault: " + err.Error()
			return res
		}
		return deliverForgejoSecret(ctx, target, newValue, string(token.Reveal()))
	case "github_secret":
		token, err := vaultStore.Get(ctx, target.SecretID)
		if err != nil {
			res.Error = "vault: " + err.Error()
			return res
		}
		return deliverGitHubSecret(ctx, target, newValue, string(token.Reveal()))
	case "dockyard_vault":
		token, err := vaultStore.Get(ctx, target.SecretID)
		if err != nil {
			res.Error = "vault: " + err.Error()
			return res
		}
		return deliverDockyardVault(ctx, target, newValue, string(token.Reveal()))
	default:
		res.Error = fmt.Sprintf("unsupported target kind %q", target.Kind)
		return res
	}
}

// deliverWebhook is the single-phase path: one POST, body has both
// value + previous, receiver replaces atomically.
func deliverWebhook(ctx context.Context, target credentials.Target, oldValue, newValue string, hmacKey []byte) DeliveryResult {
	res := DeliveryResult{Target: target}
	body, _ := json.Marshal(DeliveryPayload{
		Key:      target.KeyName,
		Value:    newValue,
		Previous: oldValue,
	})
	resp, err := postSigned(ctx, target.URL, body, hmacKey, target.KeyName, "")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Status = resp
	res.Success = resp >= 200 && resp < 300
	if !res.Success {
		res.Error = fmt.Sprintf("HTTP %d", resp)
	}
	return res
}

// deliverReloadEndpoint runs the dual-phase grace flow. Phase 1 (open)
// deploys the new value alongside the old one; sleep grace_seconds
// (default 60s, tunable per-target) so in-flight requests on the old
// key drain; Phase 2 (close) clears the previous-value field. If
// either phase 4xx/5xx's, the rotation is recorded as failed and the
// receiver is left in whatever state it reached. Operators can re-run
// the rotation; the dockyard pattern accepts the same payload twice.
func deliverReloadEndpoint(ctx context.Context, target credentials.Target, oldValue, newValue string, hmacKey []byte) DeliveryResult {
	res := DeliveryResult{Target: target}
	grace := time.Duration(target.GraceSeconds) * time.Second
	if grace <= 0 {
		grace = defaultGrace
	}

	// Phase 1: open grace. Body carries new + old.
	openBody, _ := json.Marshal(DeliveryPayload{
		Key:      target.KeyName,
		Value:    newValue,
		Previous: oldValue,
		Phase:    "open",
	})
	openStatus, err := postSigned(ctx, target.URL, openBody, hmacKey, target.KeyName, "open")
	if err != nil {
		res.Error = "phase=open: " + err.Error()
		return res
	}
	if openStatus < 200 || openStatus >= 300 {
		res.Status = openStatus
		res.Error = fmt.Sprintf("phase=open HTTP %d", openStatus)
		return res
	}

	// Hold the grace window.
	select {
	case <-ctx.Done():
		res.Error = "phase=close: context cancelled mid-grace"
		return res
	case <-time.After(grace):
	}

	// Phase 2: close grace. Body carries new only (Previous="" tells
	// the receiver to drop the dual-validity acceptance).
	closeBody, _ := json.Marshal(DeliveryPayload{
		Key:   target.KeyName,
		Value: newValue,
		Phase: "close",
	})
	closeStatus, err := postSigned(ctx, target.URL, closeBody, hmacKey, target.KeyName, "close")
	if err != nil {
		res.Status = closeStatus
		res.Error = "phase=close: " + err.Error()
		return res
	}
	res.Status = closeStatus
	if closeStatus < 200 || closeStatus >= 300 {
		res.Error = fmt.Sprintf("phase=close HTTP %d", closeStatus)
		return res
	}
	res.Success = true
	return res
}

// defaultGrace mirrors the dockyard rotation engine's default; per-
// rotator overrides land on the Target.GraceSeconds field.
var defaultGrace = 60 * time.Second

// postSigned issues a single HMAC-signed POST. Returns the HTTP status
// code (or 0 on transport error) plus an error.
func postSigned(ctx context.Context, url string, body, hmacKey []byte, keyName, phase string) (int, error) {
	sig := signBody(body, hmacKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Reactor-Signature", "sha256="+sig)
	if keyName != "" {
		req.Header.Set("X-Reactor-Key-Name", keyName)
	}
	if phase != "" {
		req.Header.Set("X-Reactor-Phase", phase)
	}
	resp, err := DeliveryHTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	return resp.StatusCode, nil
}

// signBody computes hex(HMAC-SHA256(body, secret)). The constant-time
// comparison happens on the receiver side via crypto/subtle; producing
// the signature has no timing concerns.
func signBody(body, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// deliverFileWrite atomically replaces the file at target.URL with the
// new value. Used when a downstream consumer reads its secret from disk
// (e.g. a docker-compose env_file, a systemd EnvironmentFile, or a
// dropin under /etc/<service>/secret.env). Mode 0600 so the file is
// readable only by the daemon's user.
//
// The write is a write-to-temp + fsync + rename so a crash mid-write
// leaves the previous value intact instead of a half-written file.
func deliverFileWrite(target credentials.Target, newValue string) DeliveryResult {
	res := DeliveryResult{Target: target}
	// Containment guard: file_write drops the rotated PLAINTEXT secret onto
	// disk, so an unconstrained target.URL ("/etc/cron.d/x",
	// "~/.ssh/authorized_keys") is an arbitrary-secret-write primitive. Require
	// an operator-set base directory and refuse anything outside it; disabled
	// (refused) when REACTOR_FILE_WRITE_ROOT is unset.
	root := os.Getenv("REACTOR_FILE_WRITE_ROOT")
	if root == "" {
		res.Error = "file_write delivery disabled: set REACTOR_FILE_WRITE_ROOT to the permitted base directory"
		return res
	}
	path := filepath.Clean(target.URL)
	if rel, relErr := filepath.Rel(root, path); !filepath.IsAbs(path) || relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		res.Error = fmt.Sprintf("file_write target %q is outside REACTOR_FILE_WRITE_ROOT (%s)", target.URL, root)
		return res
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".reactor-rotate-*")
	if err != nil {
		res.Error = "create temp: " + err.Error()
		return res
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(newValue); err != nil {
		tmp.Close()
		res.Error = "write: " + err.Error()
		return res
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		res.Error = "fsync: " + err.Error()
		return res
	}
	if err := tmp.Close(); err != nil {
		res.Error = "close: " + err.Error()
		return res
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		res.Error = "chmod: " + err.Error()
		return res
	}
	if err := os.Rename(tmpPath, path); err != nil {
		res.Error = "rename: " + err.Error()
		return res
	}
	cleanup = false
	res.Success = true
	return res
}

// deliverGitHubSecret pushes the new value to a GitHub Actions repository
// secret. GitHub requires the secret to be encrypted with libsodium's
// crypto_box_seal against the repository's X25519 public key first, then
// the base64-encoded ciphertext is PUT to the secrets endpoint.
//
// target.URL is the repo API base (e.g.
// https://api.github.com/repos/owner/repo); target.KeyName is the secret
// name; the vault credential at target.SecretID holds the GitHub PAT or
// fine-grained token with secrets:write scope.
//
// Two-step:
//
//	GET  {url}/actions/secrets/public-key   -> {"key_id","key"}
//	PUT  {url}/actions/secrets/{name}        body: {"encrypted_value","key_id"}
func deliverGitHubSecret(ctx context.Context, target credentials.Target, newValue, apiToken string) DeliveryResult {
	res := DeliveryResult{Target: target}
	apiBase := strings.TrimRight(target.URL, "/")

	pubKeyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/actions/secrets/public-key", nil)
	if err != nil {
		res.Error = "build public-key request: " + err.Error()
		return res
	}
	pubKeyReq.Header.Set("Accept", "application/vnd.github+json")
	pubKeyReq.Header.Set("Authorization", "Bearer "+apiToken)
	pubKeyReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	pubKeyResp, err := DeliveryHTTPClient.Do(pubKeyReq)
	if err != nil {
		res.Error = "get public key: " + err.Error()
		return res
	}
	pubKeyBody, readErr := readBoundedProviderResponse(pubKeyResp.Body, 16<<10)
	pubKeyResp.Body.Close()
	if readErr != nil {
		res.Error = "read public key: " + readErr.Error()
		return res
	}
	if pubKeyResp.StatusCode < 200 || pubKeyResp.StatusCode >= 300 {
		res.Status = pubKeyResp.StatusCode
		res.Error = fmt.Sprintf("get public key: HTTP %d", pubKeyResp.StatusCode)
		return res
	}
	var pk struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := json.Unmarshal(pubKeyBody, &pk); err != nil {
		res.Error = "parse public key: " + err.Error()
		return res
	}
	if pk.Key == "" || pk.KeyID == "" {
		res.Error = "public key response missing fields"
		return res
	}
	rawKey, err := base64.StdEncoding.DecodeString(pk.Key)
	if err != nil {
		res.Error = "decode public key: " + err.Error()
		return res
	}
	if len(rawKey) != 32 {
		res.Error = fmt.Sprintf("public key length %d, want 32", len(rawKey))
		return res
	}
	var recipient [32]byte
	copy(recipient[:], rawKey)
	sealed, err := box.SealAnonymous(nil, []byte(newValue), &recipient, rand.Reader)
	if err != nil {
		res.Error = "seal: " + err.Error()
		return res
	}
	encrypted := base64.StdEncoding.EncodeToString(sealed)

	putBody, _ := json.Marshal(map[string]string{
		"encrypted_value": encrypted,
		"key_id":          pk.KeyID,
	})
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut,
		apiBase+"/actions/secrets/"+url.PathEscape(target.KeyName),
		bytes.NewReader(putBody))
	if err != nil {
		res.Error = "build put request: " + err.Error()
		return res
	}
	putReq.Header.Set("Accept", "application/vnd.github+json")
	putReq.Header.Set("Authorization", "Bearer "+apiToken)
	putReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := DeliveryHTTPClient.Do(putReq)
	if err != nil {
		res.Error = "put: " + err.Error()
		return res
	}
	defer putResp.Body.Close()
	_, _ = io.CopyN(io.Discard, putResp.Body, 4<<10)
	res.Status = putResp.StatusCode
	if putResp.StatusCode < 200 || putResp.StatusCode >= 300 {
		res.Error = fmt.Sprintf("put HTTP %d", putResp.StatusCode)
		return res
	}
	res.Success = true
	return res
}

// deliverDockyardVault PUTs the rotated value to a Dockyard vault entry
// via the standard `PUT /api/vault/{id}` endpoint with body
// {"value":"<new>"}. Dockyard re-encrypts in place and resets
// last_rotated_at. Auth is Bearer with a Dockyard API token.
//
// This is how Hephaestus deploy secrets get rotated end-to-end:
// Hephaestus reads from the Dockyard vault at deploy time, so updating
// the Dockyard entry IS the Hephaestus rotation.
//
// target.URL is the full entry endpoint (e.g.
// https://dockyard.example.com/api/vault/<entry-id>);
// target.SecretID is the vault credential holding the Dockyard API
// token. target.KeyName is unused (the entry id is in the URL).
func deliverDockyardVault(ctx context.Context, target credentials.Target, newValue, apiToken string) DeliveryResult {
	res := DeliveryResult{Target: target}
	body, _ := json.Marshal(map[string]string{"value": newValue})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.URL, bytes.NewReader(body))
	if err != nil {
		res.Error = "build request: " + err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := DeliveryHTTPClient.Do(req)
	if err != nil {
		res.Error = "put: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	res.Status = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	res.Success = true
	return res
}

// deliverForgejoSecret pushes the new value to a Forgejo Actions secret
// via the API. target.URL is the repo API base (e.g.
// https://forgejo.example.com/api/v1/repos/owner/repo); target.KeyName is
// the secret name; the vault credential at target.SecretID holds the
// Forgejo API token used to authenticate the call.
//
// Forgejo accepts the Gitea-compatible PUT endpoint:
//
//	PUT {url}/actions/secrets/{name}
//	Authorization: token {api_token}
//	{"data": "<new_value>"}
func deliverForgejoSecret(ctx context.Context, target credentials.Target, newValue, apiToken string) DeliveryResult {
	res := DeliveryResult{Target: target}
	endpoint := strings.TrimRight(target.URL, "/") + "/actions/secrets/" + url.PathEscape(target.KeyName)
	body, _ := json.Marshal(map[string]string{"data": newValue})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		res.Error = "build request: " + err.Error()
		return res
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "token "+apiToken)
	resp, err := DeliveryHTTPClient.Do(req)
	if err != nil {
		res.Error = "post: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	res.Status = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	res.Success = true
	return res
}

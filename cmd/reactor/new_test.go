package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRendersCronEcho(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := cmdNew(context.Background(), slog.Default(), []string{"cron-echo", "my-test", "--dest=" + dir}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"main.go", "dag.json", "README.md"} {
		path := filepath.Join(dir, "my-test", f)
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
		if !strings.Contains(string(body), "my-test") {
			t.Fatalf("%s did not substitute slug", f)
		}
	}
}

func TestWorkflowRegisterHintCarriesDAGProvenance(t *testing.T) {
	hint := workflowRegisterHint("customer-signing")
	for _, want := range []string{"--slug customer-signing", "--src main.go", "--dag dag.json", "--artifact-sha256 <sha256-printed-by-build>"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("register hint %q missing %q", hint, want)
		}
	}
}

func TestNewAcceptsDocumentedSeparatedDestAfterPositionals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := cmdNew(context.Background(), slog.Default(), []string{"cron-echo", "separated-dest", "--dest", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "separated-dest", "main.go")); err != nil {
		t.Fatalf("rendered scaffold missing from --dest directory: %v", err)
	}
}

func TestNewRefusesUnknownTemplate(t *testing.T) {
	t.Parallel()
	err := cmdNew(context.Background(), slog.Default(), []string{"does-not-exist", "my-test", "--dest", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "unknown template") {
		t.Fatalf("got %v, want unknown-template error", err)
	}
}

func TestNewRefusesBadSlug(t *testing.T) {
	t.Parallel()
	err := cmdNew(context.Background(), slog.Default(), []string{"cron-echo", "../escape", "--dest", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("got %v, want slug regex error", err)
	}
}

func TestNewRefusesOverwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "exists"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := cmdNew(context.Background(), slog.Default(), []string{"cron-echo", "exists", "--dest=" + dir})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("got %v, want already-exists error", err)
	}
}

func TestNewAllTemplatesRender(t *testing.T) {
	t.Parallel()
	for _, tpl := range availableTemplates {
		t.Run(tpl, func(t *testing.T) {
			dir := t.TempDir()
			if err := cmdNew(context.Background(), slog.Default(), []string{tpl, "smoke", "--dest=" + dir}); err != nil {
				t.Fatalf("template %s failed: %v", tpl, err)
			}
		})
	}
}

func TestNewRendersHashESignBridge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := cmdNew(context.Background(), slog.Default(), []string{"hash-esign-bridge", "partner-signing", "--dest=" + dir}); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"main.go", "dag.json", "README.md", "google-apps-script.gs"} {
		body, err := os.ReadFile(filepath.Join(dir, "partner-signing", file))
		if err != nil {
			t.Fatalf("missing %s: %v", file, err)
		}
		if !strings.Contains(string(body), "partner-signing") {
			t.Fatalf("%s did not substitute slug", file)
		}
	}
	checks := map[string][]string{
		"main.go": {
			`WebhookTrigger{Provider: "automation-v1"}`,
			"func (p *hashRetryPolicy) MaxAttempts() int",
			`errors.New("invalid e-signature request event")`,
			`errors.New("unconfigured e-signature template profile")`,
		},
		"dag.json": {`"provider": "automation-v1"`},
		"README.md": {
			"--value-file",
			"--artifact-sha256",
			"X-Webhook-Timestamp",
			"/status?delivery_id=",
			"reconcileHashESignRequest",
			"at least 32 UTF-8 bytes",
			"verifyResponseContentTypeTestVectors",
			"verifyPreparationValidationTestVectors",
			"development-only",
		},
		"google-apps-script.gs": {
			"timestamp + '.' + stableEventId + '.' + body",
			"timestamp + '.' + stableEventId + '.';",
			"config.webhook_url + '/status?delivery_id='",
			"encodeURIComponent(stableEventId)",
			"function reconcileHashESignRequest",
			"method: 'get'",
			"'X-Webhook-Timestamp': timestamp",
			"followRedirects: false",
			"verifyAutomationV1HmacTestVector",
			"status === 425",
			"hasOnlyKeys_(receipt, ['accepted', 'deduped', 'run_id'])",
			"receipt = parseStrictJSON_(receiptText)",
			"statusReceipt = parseStrictJSON_(responseText)",
			"persistedEvent = parseStrictJSON_(delivery.raw_body)",
			"function rejectDuplicateJSONNames_",
			"Object.prototype.hasOwnProperty.call(names, name)",
			"function verifyStrictJSONParserTestVectors",
			"function hasExactJSONContentType_",
			"response.getAllHeaders()",
			"utf8ByteLength_(webhookSecret) < 32",
			"function verifyResponseContentTypeTestVectors",
			"function verifyPreparationValidationTestVectors",
			"customer.variables must be a plain object",
			"customer.expiresAt must be at least 10 minutes after occurredAt",
			"^[A-Za-z_][A-Za-z0-9_.]*$",
			"Active status must not contain a Hash result",
			"f6e89ca3873375b9fa59d935a6dbc7f92bedd1743b975ae05e47756845d765ab",
		},
	}
	for file, wants := range checks {
		body, err := os.ReadFile(filepath.Join(dir, "partner-signing", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s missing automation-v1 contract %q", file, want)
			}
		}
	}
	readme, err := os.ReadFile(filepath.Join(dir, "partner-signing", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(readme), "/runs/{run_id}") {
		t.Fatal("generated bridge still directs webhook producers to the dashboard run endpoint")
	}
	mainSource, err := os.ReadFile(filepath.Join(dir, "partner-signing", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{
		"unconfigured e-signature profile %q",
	} {
		if strings.Contains(string(mainSource), unsafe) {
			t.Fatalf("generated bridge can expose producer-controlled validation detail through %q", unsafe)
		}
	}
}

func TestNewRendersHashESignLifecycle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := cmdNew(context.Background(), slog.Default(), []string{
		"hash-esign-lifecycle", "partner-lifecycle", "--dest=" + dir,
	}); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"main.go", "dag.json", "README.md"} {
		body, err := os.ReadFile(filepath.Join(dir, "partner-lifecycle", file))
		if err != nil {
			t.Fatalf("missing %s: %v", file, err)
		}
		if !strings.Contains(string(body), "partner-lifecycle") {
			t.Fatalf("%s did not substitute slug", file)
		}
	}
	checks := map[string][]string{
		"main.go": {
			`WebhookTrigger{Provider: "hash-v1"}`,
			"func (p *crmRetryPolicy) MaxAttempts() int",
			"trustedHashOrgID",
			"trustedBrightCRMBaseURL",
			"brightcrm-esign-lifecycle-partner-lifecycle",
			"DecodeLifecycleEvent(raw, trustedHashOrgID)",
			"errors.Is(err, hashesign.ErrUncorrelatedDocument)",
			`"event_id", event.EventID`,
			"DeliverLifecycleEvent(ctx, event)",
			"brightcrm.IsRetryable(err)",
		},
		"dag.json": {
			`"provider": "hash-v1"`,
			`"attempts": 12`,
		},
		"README.md": {
			"esign:lifecycle",
			"--artifact-sha256",
			"Google Secret Manager",
			"out-of-order",
			"document.changes_requested",
			"successful no-op",
			"forwards Hash `payload`, recipient data, customer data",
			"document.created` are intentionally rejected",
		},
	}
	for file, wants := range checks {
		body, err := os.ReadFile(filepath.Join(dir, "partner-lifecycle", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s missing lifecycle contract %q", file, want)
			}
		}
	}
}

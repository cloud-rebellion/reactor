package commandwebhook_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/reactor/internal/vault"
	"github.com/go-chi/chi/v5"
)

type refusingFlareVault struct{ reads int }

func (v *refusingFlareVault) Get(context.Context, string) (*vault.Secret, error) {
	v.reads++
	return vault.NewSecret([]byte(commandWebhookTestSecret)), nil
}

func TestCommandReceiverRefusesRestoredFlareProviderBeforeSecretOrRun(t *testing.T) {
	h := newCommandWebhookHarness(t, "acme")
	if _, err := h.db.ExecContext(context.Background(), `UPDATE command_automation_webhook_triggers SET provider='flare-v1' WHERE id=?`, h.trigger.ID); err != nil {
		t.Fatal(err)
	}
	keys := &refusingFlareVault{}
	h.receiver.Vault = keys
	router := chi.NewRouter()
	h.receiver.Mount(router)
	req := httptest.NewRequest(http.MethodPost, "/command-webhook/"+h.trigger.TokenID, strings.NewReader(`{"schema":"flare.automation.v1"}`))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 404 || keys.reads != 0 {
		t.Fatalf("restored Flare command trigger=%d key reads=%d", w.Code, keys.reads)
	}
	var count int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM command_runs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("command runs=%d %v", count, err)
	}
}

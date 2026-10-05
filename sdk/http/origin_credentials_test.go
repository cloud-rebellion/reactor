package http

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	reactor "github.com/bright-interaction/reactor/sdk"
)

func TestCredentialClientRejectsMissingAndForeignInitialOriginsBeforeTransport(t *testing.T) {
	for _, tc := range []struct {
		name, pin, target string
		bearer            string
		headers           map[string]string
	}{
		{name: "missing bearer pin", target: "https://api.example.test/data?cursor=sensitive", bearer: "secret"},
		{name: "missing static header pin", target: "https://api.example.test/data", headers: map[string]string{"X-Api-Key": "secret"}},
		{name: "missing version header pin", target: "https://api.example.test/data", headers: map[string]string{"Notion-Version": "2022-06-28"}},
		{name: "foreign host", pin: "https://api.example.test", target: "https://attacker.example.test/steal?cursor=sensitive", bearer: "secret"},
		{name: "subdomain", pin: "https://api.example.test", target: "https://sub.api.example.test/data", bearer: "secret"},
		{name: "downgrade", pin: "https://api.example.test", target: "http://api.example.test/data", bearer: "secret"},
		{name: "port", pin: "https://api.example.test", target: "https://api.example.test:444/data", bearer: "secret"},
		{name: "pin with path", pin: "https://api.example.test/v1", target: "https://api.example.test/data", bearer: "secret"},
		{name: "pin with query", pin: "https://api.example.test?token=secret", target: "https://api.example.test/data", bearer: "secret"},
		{name: "URL userinfo", pin: "https://api.example.test", target: "https://user:secret@api.example.test/data", bearer: "secret"},
		{name: "query API key without pin", target: "https://api.example.test/data?api_key=secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &Client{
				Bearer: tc.bearer, Headers: tc.headers, CredentialOrigin: tc.pin,
				HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					return testResponse(http.StatusOK, nil, `{}`), nil
				})},
			}
			_, _, _, err := client.GetRaw(context.Background(), tc.target)
			if !errors.Is(err, ErrCredentialOrigin) || !reactor.IsPermanent(err) || calls != 0 {
				t.Fatalf("credential origin refusal = %v, transport calls = %d", err, calls)
			}
			if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("origin refusal exposed credential or URL query: %v", err)
			}
		})
	}
}

func TestCredentialOriginAcceptsEquivalentDefaultPorts(t *testing.T) {
	for _, tc := range []struct{ pin, target string }{
		{pin: "https://api.example.test:443", target: "https://api.example.test/items"},
		{pin: "https://api.example.test", target: "https://api.example.test:443/items"},
		{pin: "http://api.example.test:80", target: "http://api.example.test/items"},
	} {
		t.Run(tc.pin+" -> "+tc.target, func(t *testing.T) {
			calls := 0
			client := &Client{
				Bearer: "secret", CredentialOrigin: tc.pin,
				HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Header.Get("Authorization") != "Bearer secret" {
						t.Error("same-origin request lost authorization")
					}
					return testResponse(http.StatusOK, nil, `{}`), nil
				})},
			}
			if err := client.Get(context.Background(), tc.target, nil); err != nil || calls != 1 {
				t.Fatalf("same-origin default port = err %v, calls %d", err, calls)
			}
		})
	}
}

func TestCredentialOriginAlsoProtectsUnknownQueryCredentialNames(t *testing.T) {
	calls := 0
	client := &Client{
		CredentialOrigin: "https://api.example.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return testResponse(http.StatusOK, nil, `{}`), nil
		})},
	}
	_, _, _, err := client.GetRaw(context.Background(), "https://attacker.example.test/collect?provider_credential=sensitive")
	if !errors.Is(err, ErrCredentialOrigin) || calls != 0 || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("custom query credential was not pinned: err %v, calls %d", err, calls)
	}
}

func TestCredentialClientPinsExplicitRequestAuthorizationAndAllowsSameOrigin(t *testing.T) {
	calls := 0
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "api.example.test" || req.Header.Get("Authorization") != "Basic token" {
			t.Errorf("unexpected request origin or authorization")
		}
		return testResponse(http.StatusOK, nil, `{}`), nil
	})}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.example.test/v1/items?page=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic token")
	if _, err := client.Do(req); !errors.Is(err, ErrCredentialOrigin) || calls != 0 {
		t.Fatalf("unpinned explicit authorization = %v, calls = %d", err, calls)
	}
	client.CredentialOrigin = "https://API.example.test"
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || calls != 1 {
		t.Fatalf("same-origin authorization = response %v, err %v, calls %d", resp, err, calls)
	}
	_ = resp.Body.Close()
}

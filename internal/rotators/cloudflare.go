package rotators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bright-interaction/reactor/internal/safehttp"
)

// defaultp.apiBase() is the production endpoint. Tests construct
// a CloudflareProvider with APIBase set to an httptest.Server URL so
// concurrent tests never share-mutate a package-level string.
const defaultCloudflareAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareHTTPClient is the shared client; bounded timeout prevents a
// stuck Cloudflare endpoint from holding up the rotation runner.
// The API base is operator-configurable for tests and private enterprise
// gateways. Keep the provider client behind the same connect-time SSRF guard
// as webhook delivery so a bad base can never reach link-local metadata (or
// follow a redirect there) while carrying the current bearer token.
var cloudflareHTTPClient = safehttp.Client(true)

// CloudflareProvider rotates a Cloudflare API token in place via the
// "roll" endpoint (PUT /user/tokens/{id}/value) so existing token id
// metadata stays the same; only the bearer value changes.
//
// APIBase is the API root; empty means use the production endpoint.
// Tests inject an httptest.Server URL.
type CloudflareProvider struct {
	APIBase string
}

func (p *CloudflareProvider) apiBase() string {
	if p.APIBase != "" {
		return p.APIBase
	}
	return defaultCloudflareAPIBase
}

func (p *CloudflareProvider) Name() string        { return "cloudflare" }
func (p *CloudflareProvider) CanAutoRotate() bool { return true }

// Rotate identifies the token by calling /user/tokens/verify, then PUTs
// /user/tokens/{id}/value to roll the secret. The new bearer comes back
// in result.Result.
func (p *CloudflareProvider) Rotate(ctx context.Context, currentKey string, _ map[string]string) (string, error) {
	tokenID, err := p.getTokenID(ctx, currentKey)
	if err != nil {
		return "", fmt.Errorf("identify token: %w", err)
	}
	return p.rollToken(ctx, currentKey, tokenID)
}

// Validate reports whether the bearer still verifies. Useful before a
// rotation attempt to skip dead keys.
func (p *CloudflareProvider) Validate(ctx context.Context, key string, _ map[string]string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase()+"/user/tokens/verify", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := readBoundedProviderResponse(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return false, err
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false, err
	}
	return out.Success, nil
}

func (p *CloudflareProvider) getTokenID(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase()+"/user/tokens/verify", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := readBoundedProviderResponse(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return "", err
	}
	var out struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if !out.Success || out.Result.ID == "" {
		return "", fmt.Errorf("token verification failed: %s", trim(body))
	}
	return out.Result.ID, nil
}

func (p *CloudflareProvider) rollToken(ctx context.Context, currentToken, tokenID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.apiBase()+"/user/tokens/"+tokenID+"/value", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+currentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := readBoundedProviderResponse(resp.Body, maxProviderResponseBytes)
	if err != nil {
		return "", err
	}
	var out struct {
		Success bool   `json:"success"`
		Result  string `json:"result"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if !out.Success || out.Result == "" {
		msgs := make([]string, 0, len(out.Errors))
		for _, e := range out.Errors {
			msgs = append(msgs, e.Message)
		}
		return "", fmt.Errorf("roll failed: %s", strings.Join(msgs, "; "))
	}
	return out.Result, nil
}

// trim caps an error excerpt; the API can echo full request bodies on
// failure and we don't want those in logs.
func trim(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

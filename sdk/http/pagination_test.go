package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func decodeTestPage(body []byte, headers map[string]string) (Page[string], error) {
	var payload struct {
		Items []string `json:"items"`
		Next  string   `json:"next"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Page[string]{}, err
	}
	if headers["X-Next-Page"] != "" {
		payload.Next = headers["X-Next-Page"]
	}
	return Page[string]{Items: payload.Items, Next: payload.Next}, nil
}

func TestFetchPagesFollowsRelativeCursorAndPreservesAuth(t *testing.T) {
	var paths []string
	client := &Client{
		Bearer: "test-secret", CredentialOrigin: "https://api.example.test",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer test-secret" {
				t.Errorf("missing auth on %s", req.URL)
			}
			paths = append(paths, req.URL.String())
			switch req.URL.RawQuery {
			case "page=1":
				return testResponse(http.StatusOK, http.Header{"X-Next-Page": []string{"?page=2"}}, `{"items":["a"]}`), nil
			case "page=2":
				return testResponse(http.StatusOK, nil, `{"items":["b"],"next":""}`), nil
			default:
				t.Fatalf("unexpected request: %s", req.URL)
				return nil, nil
			}
		})},
	}
	batch, err := FetchPages(context.Background(), client, "https://api.example.test/v1/items?page=1", PageLimits{}, decodeTestPage)
	if err != nil {
		t.Fatalf("fetch pages: %v", err)
	}
	if !batch.Complete || batch.NextURL != "" || batch.Pages != 2 || batch.Bytes == 0 || strings.Join(batch.Items, ",") != "a,b" {
		t.Fatalf("unexpected batch: %+v", batch)
	}
	if len(paths) != 2 || paths[1] != "https://api.example.test/v1/items?page=2" {
		t.Fatalf("requested URLs: %v", paths)
	}
}

func TestFetchPagesReturnsResumableBatchAtPageBoundary(t *testing.T) {
	var hits int
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hits++
		switch req.URL.Query().Get("page") {
		case "1":
			return testResponse(http.StatusOK, nil, `{"items":["a"],"next":"?page=2"}`), nil
		case "2":
			return testResponse(http.StatusOK, nil, `{"items":["b"],"next":"?page=3"}`), nil
		case "3":
			return testResponse(http.StatusOK, nil, `{"items":["c"]}`), nil
		default:
			t.Fatalf("unexpected page: %s", req.URL)
			return nil, nil
		}
	})}}
	first, err := FetchPages(context.Background(), client, "https://api.example.test/items?page=1", PageLimits{MaxPages: 2}, decodeTestPage)
	if err != nil || first.Complete || first.Pages != 2 || first.NextURL != "https://api.example.test/items?page=3" || strings.Join(first.Items, ",") != "a,b" || hits != 2 {
		t.Fatalf("first batch = %+v, hits = %d, err = %v", first, hits, err)
	}
	second, err := FetchPages(context.Background(), client, first.NextURL, PageLimits{MaxPages: 2}, decodeTestPage)
	if err != nil || !second.Complete || second.NextURL != "" || strings.Join(second.Items, ",") != "c" || hits != 3 {
		t.Fatalf("resumed batch = %+v, hits = %d, err = %v", second, hits, err)
	}
}

func TestFetchPagesRejectsUnsafeNextURLBeforeSendingCredential(t *testing.T) {
	for _, next := range []string{
		"https://other.example.test/items", "//other.example.test/items", "http://api.example.test/items",
		"https://user:password@api.example.test/items", "javascript:alert(1)", "?page=2#fragment",
	} {
		t.Run(next, func(t *testing.T) {
			var hits int
			client := &Client{Bearer: "test-secret", CredentialOrigin: "https://api.example.test", HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				hits++
				return testResponse(http.StatusOK, nil, `{"items":["a"],"next":`+jsonString(next)+`}`), nil
			})}}
			batch, err := FetchPages(context.Background(), client, "https://api.example.test/items", PageLimits{}, decodeTestPage)
			if !errors.Is(err, ErrPageURL) || hits != 1 || batch.Pages != 0 || len(batch.Items) != 0 {
				t.Fatalf("unsafe next = %q: batch=%+v hits=%d err=%v", next, batch, hits, err)
			}
		})
	}
}

func TestFetchPagesRejectsCycleBeforeSecondRequest(t *testing.T) {
	var hits int
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		hits++
		return testResponse(http.StatusOK, nil, `{"items":["a"],"next":"?page=1"}`), nil
	})}}
	_, err := FetchPages(context.Background(), client, "https://api.example.test/items?page=1", PageLimits{}, decodeTestPage)
	if !errors.Is(err, ErrPageURL) || hits != 1 {
		t.Fatalf("cycle = %v, hits = %d; want URL error before repeat", err, hits)
	}
}

func TestFetchPagesRefusesRedirectWithInjectedClient(t *testing.T) {
	var sourceHits, targetHits int
	client := &Client{Bearer: "test-secret", CredentialOrigin: "https://api.example.test", HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.example.test" {
			sourceHits++
			return testResponse(http.StatusFound, http.Header{"Location": []string{"https://attacker.example.test/steal"}}, "redirect"), nil
		}
		targetHits++
		if req.Header.Get("Authorization") != "" {
			t.Errorf("redirect target received credential")
		}
		return testResponse(http.StatusOK, nil, `{"items":[]}`), nil
	})}}
	_, err := FetchPages(context.Background(), client, "https://api.example.test/items", PageLimits{}, decodeTestPage)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusFound || sourceHits != 1 || targetHits != 0 {
		t.Fatalf("redirect: source=%d target=%d err=%v", sourceHits, targetHits, err)
	}
}

func TestFetchPagesFailsClosedOnItemAndByteLimits(t *testing.T) {
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, nil, `{"items":["a","b"]}`), nil
	})}}
	for _, limits := range []PageLimits{{MaxItems: 1}, {MaxBytes: 4}} {
		batch, err := FetchPages(context.Background(), client, "https://api.example.test/items", limits, decodeTestPage)
		if !errors.Is(err, ErrPageLimit) || batch.Pages != 0 || len(batch.Items) != 0 {
			t.Fatalf("limits %+v: batch=%+v err=%v", limits, batch, err)
		}
	}
	if _, err := FetchPages(context.Background(), client, "https://api.example.test/items", PageLimits{MaxPages: hardMaxPages + 1}, decodeTestPage); !errors.Is(err, ErrPageLimit) {
		t.Fatalf("hard ceiling error = %v", err)
	}
}

func TestFetchPagesReturnsTypedRateLimitWithoutPartialData(t *testing.T) {
	var hits int
	client := &Client{Retry: Retry{Max: 2}, HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hits++
		if req.URL.Query().Get("page") == "1" {
			return testResponse(http.StatusOK, nil, `{"items":["a"],"next":"?page=2"}`), nil
		}
		return testResponse(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"3600"}}, "slow down"), nil
	})}}
	batch, err := FetchPages(context.Background(), client, "https://api.example.test/items?page=1", PageLimits{}, decodeTestPage)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests || !apiErr.RetryAfterLong || hits != 2 || batch.Pages != 0 {
		t.Fatalf("rate limit: batch=%+v hits=%d err=%v", batch, hits, err)
	}
}

func TestFetchPagesSanitizesDecoderFailureAfterEarlierPage(t *testing.T) {
	const private = "customer@example.test-secret-cursor"
	var hits int
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hits++
		if req.URL.Query().Get("page") == "1" {
			return testResponse(http.StatusOK, nil, `{"items":["safe"],"next":"?page=2"}`), nil
		}
		return testResponse(http.StatusOK, nil, `{"cursor":"`+private+`"}`), nil
	})}}
	decode := func(body []byte, headers map[string]string) (Page[string], error) {
		if strings.Contains(string(body), private) {
			return Page[string]{}, fmt.Errorf("provider decoder failed on %s", body)
		}
		return decodeTestPage(body, headers)
	}
	batch, err := FetchPages(context.Background(), client, "https://api.example.test/items?page=1", PageLimits{}, decode)
	if !errors.Is(err, ErrResponseDecode) || strings.Contains(err.Error(), private) || hits != 2 || batch.Pages != 0 || len(batch.Items) != 0 {
		t.Fatalf("decoder error = %v, hits = %d, batch = %+v; want sanitized, empty failure", err, hits, batch)
	}
}

func TestFetchPagesRejectsOversizedProviderBody(t *testing.T) {
	client := &Client{HTTPClient: &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+1)))}, nil
	})}}
	_, err := FetchPages(context.Background(), client, "https://api.example.test/items", PageLimits{}, decodeTestPage)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized body error = %v", err)
	}
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

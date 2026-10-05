package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPageLimit reports that a provider page cannot fit within the caller's
// explicit batch limits. No partial batch is returned in that case.
var ErrPageLimit = errors.New("reactor: pagination limit exceeded")

// ErrPageURL reports an invalid or unsafe provider-supplied next-page URL.
var ErrPageURL = errors.New("reactor: invalid pagination URL")

const (
	defaultMaxPages = 10
	defaultMaxItems = 1000
	defaultMaxBytes = 16 << 20
	hardMaxPages    = 100
	hardMaxItems    = 10000
	hardMaxBytes    = 64 << 20
	maxPageURLBytes = 8192
)

// PageLimits bound one batch. Zero fields use the defaults. The hard ceilings
// prevent a generated workflow from silently allocating an unbounded result.
// Every individual response also uses Client.GetRaw's 4 MiB body limit.
type PageLimits struct {
	MaxPages int
	MaxItems int
	MaxBytes int
}

// Page is the provider-specific decoder's normalized result. Next may be an
// absolute URL or a relative reference; empty means there are no more pages.
type Page[T any] struct {
	Items []T
	Next  string
}

// PageDecoder adapts a provider's JSON body and response headers to Page.
// Keep it pure: a failed batch is retried from the first page, and the decoder
// must not issue mutations or emit side effects.
type PageDecoder[T any] func(body []byte, headers map[string]string) (Page[T], error)

// PageBatch contains only complete pages. A non-empty NextURL means the caller
// should fetch another batch from that URL in a later durable Step, after
// persisting or processing this batch. Treat NextURL as provider data: some
// providers put sensitive cursor material in the query string.
type PageBatch[T any] struct {
	Items    []T
	NextURL  string
	Pages    int
	Bytes    int
	Complete bool
}

// FetchPages reads a bounded batch of JSON pages through the normal SDK HTTP
// policy. It never retries mutations, follows only same-origin pagination
// references, detects URL cycles, and returns no partial result on errors.
// The provider adapter is responsible for decoding its documented item and
// continuation shapes; catalog metadata alone is not a provider contract.
func FetchPages[T any](ctx context.Context, c *Client, startURL string, limits PageLimits, decode PageDecoder[T]) (PageBatch[T], error) {
	var empty PageBatch[T]
	if c == nil || decode == nil {
		return empty, errors.New("reactor: pagination requires a client and decoder")
	}
	limits, err := normalizePageLimits(limits)
	if err != nil {
		return empty, err
	}
	origin, err := parsePageURL(startURL)
	if err != nil {
		return empty, err
	}
	current := origin.String()
	seen := make(map[string]struct{}, limits.MaxPages)
	batch := PageBatch[T]{Items: make([]T, 0)}
	// A caller-supplied HTTPClient may allow redirects. Pagination must not
	// forward its credential to an unvalidated Location, so refuse redirects
	// even for injected host-side clients. The copied client shares Transport
	// and its connection pool with the caller.
	pageClient := *c
	if c.HTTPClient != nil {
		transportClient := *c.HTTPClient
		transportClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		pageClient.HTTPClient = &transportClient
	}
	for batch.Pages < limits.MaxPages {
		if _, duplicate := seen[current]; duplicate {
			return empty, fmt.Errorf("%w: pagination cycle", ErrPageURL)
		}
		seen[current] = struct{}{}
		status, headers, body, err := pageClient.GetRaw(ctx, current)
		if err != nil {
			return empty, err
		}
		if len(body) > limits.MaxBytes-batch.Bytes {
			return empty, fmt.Errorf("%w: response bytes exceed %d", ErrPageLimit, limits.MaxBytes)
		}
		if status < 200 || status >= 300 {
			after, valid, tooLong := retryAfter(headers["Retry-After"], time.Now())
			if !valid {
				after = 0
			}
			return empty, &Error{Status: status, Body: string(body), RetryAfter: after, RetryAfterLong: tooLong}
		}
		page, err := decode(body, headers)
		if err != nil {
			// Provider data and custom decoder errors are untrusted. Their text
			// can contain response bodies, cursors, or even credential headers;
			// keep it out of the durable Step error and operator logs.
			return empty, fmt.Errorf("decode provider page %d: %w", batch.Pages+1, ErrResponseDecode)
		}
		if len(page.Items) > limits.MaxItems-len(batch.Items) {
			return empty, fmt.Errorf("%w: items exceed %d", ErrPageLimit, limits.MaxItems)
		}
		batch.Items = append(batch.Items, page.Items...)
		batch.Pages++
		batch.Bytes += len(body)
		if page.Next == "" {
			batch.NextURL = ""
			batch.Complete = true
			return batch, nil
		}
		currentURL, _ := url.Parse(current) // checked by parsePageURL or resolvePageURL
		next, err := resolvePageURL(origin, currentURL, page.Next)
		if err != nil {
			return empty, err
		}
		if _, duplicate := seen[next]; duplicate {
			return empty, fmt.Errorf("%w: pagination cycle", ErrPageURL)
		}
		batch.NextURL = next
		if batch.Pages == limits.MaxPages || len(batch.Items) == limits.MaxItems || batch.Bytes == limits.MaxBytes {
			return batch, nil
		}
		current = next
	}
	return batch, nil
}

func normalizePageLimits(limits PageLimits) (PageLimits, error) {
	if limits.MaxPages == 0 {
		limits.MaxPages = defaultMaxPages
	}
	if limits.MaxItems == 0 {
		limits.MaxItems = defaultMaxItems
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = defaultMaxBytes
	}
	if limits.MaxPages < 1 || limits.MaxPages > hardMaxPages || limits.MaxItems < 1 || limits.MaxItems > hardMaxItems || limits.MaxBytes < 1 || limits.MaxBytes > hardMaxBytes {
		return PageLimits{}, fmt.Errorf("%w: limits must be within pages=1..%d, items=1..%d, bytes=1..%d", ErrPageLimit, hardMaxPages, hardMaxItems, hardMaxBytes)
	}
	return limits, nil
}

func parsePageURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > maxPageURLBytes {
		return nil, fmt.Errorf("%w: URL length", ErrPageURL)
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: expected an absolute HTTP URL without userinfo or fragment", ErrPageURL)
	}
	return u, nil
}

func resolvePageURL(origin, current *url.URL, raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxPageURLBytes {
		return "", fmt.Errorf("%w: next URL length", ErrPageURL)
	}
	ref, err := url.Parse(raw)
	if err != nil || ref == nil || ref.User != nil || ref.Fragment != "" || ref.Opaque != "" {
		return "", fmt.Errorf("%w: next URL has userinfo, fragment, or invalid syntax", ErrPageURL)
	}
	next := current.ResolveReference(ref)
	if !strings.EqualFold(next.Scheme, origin.Scheme) || !strings.EqualFold(next.Host, origin.Host) || next.User != nil || next.Opaque != "" || len(next.String()) > maxPageURLBytes {
		return "", fmt.Errorf("%w: next URL leaves the starting origin", ErrPageURL)
	}
	return next.String(), nil
}

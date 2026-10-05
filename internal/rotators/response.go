package rotators

import (
	"fmt"
	"io"
)

const maxProviderResponseBytes = 1 << 20

func readBoundedProviderResponse(r io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("response limit must be positive")
	}
	body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return body, nil
}

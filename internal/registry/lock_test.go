package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireSlugLockSerializesAndReleases(t *testing.T) {
	t.Parallel()
	reg := New(t.TempDir())
	first, err := reg.AcquireSlugLock(context.Background(), "shared")
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			first()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := reg.AcquireSlugLock(ctx, "shared"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock error = %v, want context deadline", err)
	}

	first()
	released = true
	second, err := reg.AcquireSlugLock(context.Background(), "shared")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second()
}

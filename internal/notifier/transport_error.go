package notifier

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// safePostError drops the original transport error. net/http wraps failures in
// url.Error, whose message and unwrap chain can contain the full request URL.
// Slack webhook URLs and generic webhook query strings may contain secrets;
// this error is logged and retained in terminal_effects.last_error.
func safePostError(sender string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: post canceled: %w", sender, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: post timed out: %w", sender, context.DeadlineExceeded)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%s: post timed out", sender)
	}
	return fmt.Errorf("%s: post failed", sender)
}

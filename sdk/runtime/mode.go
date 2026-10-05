package runtime

import "os"

// IsDryRun reports whether Reactor launched the workflow for review rather
// than live execution. Use it to select fixtures or skip business mutations;
// SDK network clients also enforce the same boundary independently.
func IsDryRun() bool { return os.Getenv("REACTOR_MODE") == "dry_run" }

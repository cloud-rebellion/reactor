package codegen

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitCommitterHonorsGitBackedSetting(t *testing.T) {
	for _, tc := range []struct {
		name       string
		env        string
		wantNoErr  bool
		wantErrSub string
	}{
		{name: "unset keeps repository commits enabled", wantErrSub: "git add"},
		{name: "true keeps repository commits enabled", env: "true", wantErrSub: "git add"},
		{name: "false disables repository commits", env: "false", wantNoErr: true},
		{name: "zero disables repository commits", env: "0", wantNoErr: true},
		{name: "off disables repository commits", env: "off", wantNoErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REACTOR_GIT_BACKED", tc.env)

			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
				t.Fatal(err)
			}
			// A missing binary proves the disabled path returns before it tries
			// to run git, while enabled paths preserve the existing error.
			committer := &GitCommitter{GitBin: filepath.Join(dir, "missing-git")}
			err := committer.CommitMessage(context.Background(), dir, "test")
			if tc.wantNoErr {
				if err != nil {
					t.Fatalf("disabled git backing returned %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("enabled git backing error = %v, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

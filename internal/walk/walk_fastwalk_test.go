//go:build !nofastwalk

package walk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// TestWalkParallelSurvivesUnreadableDirectory pins the fastwalk
// traversal against the abort it is easiest to reintroduce: fastwalk
// hands any non-nil callback return, SkipDir included, to the
// coordinator loop, which stops the whole walk. Returning SkipDir for an
// unreadable directory therefore truncated the scan at the first TCC or
// permission denial, non-deterministically and without an error the
// caller could tell apart from a skip.
func TestWalkParallelSurvivesUnreadableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	// Enough sibling subtrees that an early abort leaves work undone.
	for i := 0; i < 40; i++ {
		dir := filepath.Join(root, "sub", fmt.Sprintf("d%02d", i))
		mustMkdir(t, dir)
		mustWrite(t, filepath.Join(dir, "package-lock.json"), "{}")
	}
	locked := filepath.Join(root, "sub", "locked")
	mustMkdir(t, filepath.Join(locked, "child"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skipf("cannot make directory unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	count := func(parallel bool) int {
		var mu sync.Mutex
		n := 0
		visit := func(path string, d fs.DirEntry) error {
			mu.Lock()
			n++
			mu.Unlock()
			return nil
		}
		onErr := func(string, error) {}
		var err error
		if parallel {
			err = walkOneParallel(root, normalizeExcludes(nil), map[string]struct{}{}, onErr, visit)
		} else {
			err = walkOne(root, normalizeExcludes(nil), map[string]struct{}{}, onErr, visit)
		}
		if err != nil {
			t.Errorf("walk returned %v; an unreadable directory is reported through OnError, not the return value", err)
		}
		return n
	}

	want := count(false)
	// The truncation is a scheduling race: repeat so a regression cannot
	// pass by getting lucky once.
	for i := 0; i < 25; i++ {
		if got := count(true); got != want {
			t.Fatalf("parallel walk visited %d entries on run %d, serial visited %d", got, i, want)
		}
	}
}

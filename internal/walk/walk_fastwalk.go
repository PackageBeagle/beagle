//go:build !nofastwalk

package walk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/charlievieth/fastwalk"
)

// walkRoot uses the parallel traversal. This is the default build; see
// walk_serial.go for the `-tags nofastwalk` stdlib alternative.
func walkRoot(root string, excludes excludeSet, seen map[string]struct{}, onErr func(string, error), visit Visitor) error {
	return walkOneParallel(root, excludes, seen, onErr, visit)
}

// walkOneParallel mirrors walkOne's skip/dedup semantics but drives the
// traversal with charlievieth/fastwalk, which reads directories from a
// pool of goroutines. The shared seen map is guarded by mu; the visitor
// must itself be concurrency-safe.
//
// Two places where fastwalk's error semantics differ from WalkDir's and
// the callback has to compensate:
//
//   - A directory error must return nil, never SkipDir. fastwalk invokes
//     the callback with a non-nil err only after readDir has already
//     failed, and that return value goes straight to the coordinator
//     loop, which aborts the whole walk on any non-nil error — SkipDir
//     included. Returning SkipDir there truncated the traversal at the
//     first unreadable directory (a TCC denial is enough), losing every
//     subtree not yet dispatched. There is nothing left to skip anyway:
//     the directory could not be read.
//   - A Visitor's ErrSkip for a *file* must never reach fastwalk.
//     fastwalk hands that return value back through the readdir-error
//     path, which abandons whatever of the containing directory has not
//     been dispatched yet — measurably losing sibling subtrees — and
//     surfaces a bogus "skip this directory" error. filepath.WalkDir
//     scopes the same return differently (it abandons the rest of that
//     directory outright), so there is no shared meaning to implement.
//     onVisitError refuses it for both traversals instead; ErrStop is
//     the way to end a walk from a file.
func walkOneParallel(root string, excludes excludeSet, seen map[string]struct{}, onErr func(string, error), visit Visitor) error {
	var mu sync.Mutex
	return fastwalk.Walk(&fastwalk.Config{}, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A callback return value comes back through this same
			// parameter once readDir unwinds, so an ErrStop raised on a
			// file arrives here disguised as a directory error. Logging
			// it would swallow the stop and let the walk continue.
			if errors.Is(err, ErrStop) {
				return ErrStop
			}
			if onErr != nil {
				onErr(path, err)
			}
			return nil
		}
		if d.IsDir() {
			if isExcluded(path, d.Name(), excludes) {
				return filepath.SkipDir
			}
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			if key, ok := dirKey(path); ok {
				mu.Lock()
				_, dup := seen[key]
				if !dup {
					seen[key] = struct{}{}
				}
				mu.Unlock()
				if dup {
					return filepath.SkipDir
				}
			}
		}
		if verr := visit(path, d); verr != nil {
			return onVisitError(path, d, verr, onErr)
		}
		return nil
	})
}

//go:build nofastwalk

package walk

// walkRoot uses the stdlib filepath.WalkDir traversal. Selected by
// building with `-tags nofastwalk`, which is the escape hatch for
// anyone who needs beagle to link no third-party code at all — it costs
// roughly 3.5x on a deep scan (see docs/DESIGN.md, "Parallel traversal").
//
// The serial walker holds the only reference to seen while it runs, so
// no locking is needed here.
func walkRoot(root string, excludes excludeSet, seen map[string]struct{}, onErr func(string, error), visit Visitor) error {
	return walkOne(root, excludes, seen, onErr, visit)
}

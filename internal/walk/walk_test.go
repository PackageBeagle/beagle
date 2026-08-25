package walk

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestDefaultExcludesCoverProtectedMacOSLibraryPaths ensures the macOS
// Library subtrees that routinely produce TCC denials under broad
// $HOME scans are matched by the default suffix-component excludes.
// Adding new paths to DefaultExcludes is cheap; regressing one of
// these silently is what makes the diagnostics output scary.
func TestDefaultExcludesCoverProtectedMacOSLibraryPaths(t *testing.T) {
	want := []string{
		"Library/ContainerManager",
		"Library/Daemon Containers",
		"Library/DoNotDisturb",
		"Library/DuetExpertCenter",
		"Library/IntelligencePlatform",
		"Library/Photos",
		"Library/Sharing",
		"Library/Shortcuts",
		"Library/StatusKit",
	}
	have := make(map[string]bool, len(DefaultExcludes))
	for _, x := range DefaultExcludes {
		have[x] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("DefaultExcludes missing %q", w)
		}
	}
}

// TestWalkSkipsExcludedLibrarySubtrees verifies that an exclude with
// a "/"-separated suffix (e.g. "Library/ContainerManager") prunes a
// matching directory anywhere under any root, while a sibling
// directory that does not match continues to be walked.
func TestWalkSkipsExcludedLibrarySubtrees(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	root := t.TempDir()
	// Simulate a $HOME-shaped tree.
	mustMkdir(t, filepath.Join(root, "Library", "ContainerManager", "deep"))
	mustMkdir(t, filepath.Join(root, "Library", "StatusKit"))
	mustMkdir(t, filepath.Join(root, "code", "proj"))

	// Drop sentinel files we can detect from the visitor.
	mustWrite(t, filepath.Join(root, "Library", "ContainerManager", "deep", "secret.json"), "{}")
	mustWrite(t, filepath.Join(root, "Library", "StatusKit", "x"), "{}")
	mustWrite(t, filepath.Join(root, "code", "proj", "package-lock.json"), "{}")

	excludes := append([]string{}, DefaultExcludes...)

	var c pathCollector
	if err := Walk(Options{
		Roots:    []string{root},
		Excludes: excludes,
	}, c.files); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	seen := c.seen()
	for _, p := range seen {
		if filepath.Base(filepath.Dir(p)) == "deep" || filepath.Base(filepath.Dir(p)) == "StatusKit" {
			t.Errorf("excluded path was visited: %s", p)
		}
	}
	want := filepath.Join(root, "code", "proj", "package-lock.json")
	found := false
	for _, p := range seen {
		if p == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to visit %q; saw %v", want, seen)
	}
}

// TestWalkSkipsMarketplaceCatalogTrees verifies that plugin-marketplace
// catalog clones — browsable plugin directories whose .mcp.json files and
// lockfiles are install templates, not live configuration — are pruned,
// while the installed-plugin cache next to them and a user project that
// happens to contain a "marketplaces" directory keep being walked.
func TestWalkSkipsMarketplaceCatalogTrees(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	root := t.TempDir()

	// Catalog trees (all must be pruned).
	claudeCatalog := filepath.Join(root, ".claude", "plugins", "marketplaces",
		"claude-plugins-official", "external_plugins", "discord")
	coworkCatalog := filepath.Join(root, "Library", "Application Support", "Claude",
		"local-agent-mode-sessions", "s1", "s2", "cowork_plugins", "marketplaces",
		"knowledge-work-plugins", "sales")
	codexStaging := filepath.Join(root, ".codex", ".tmp", "bundled-marketplaces",
		"openai-bundled", "plugins", "chrome")
	// Legitimate neighbors (all must still be visited).
	installedPlugin := filepath.Join(root, ".claude", "plugins", "cache",
		"claude-plugins-official", "supabase", "0.1.11")
	userProject := filepath.Join(root, "code", "shop", "marketplaces", "etsy")

	for _, d := range []string{claudeCatalog, coworkCatalog, codexStaging, installedPlugin, userProject} {
		mustMkdir(t, d)
		mustWrite(t, filepath.Join(d, ".mcp.json"), "{}")
	}

	var c pathCollector
	if err := Walk(Options{
		Roots:    []string{root},
		Excludes: append([]string{}, DefaultExcludes...),
	}, c.files); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	seen := c.seen()
	visited := make(map[string]bool, len(seen))
	for _, p := range seen {
		visited[p] = true
	}
	for _, d := range []string{claudeCatalog, coworkCatalog, codexStaging} {
		if visited[filepath.Join(d, ".mcp.json")] {
			t.Errorf("catalog template was visited: %s", filepath.Join(d, ".mcp.json"))
		}
	}
	for _, d := range []string{installedPlugin, userProject} {
		if !visited[filepath.Join(d, ".mcp.json")] {
			t.Errorf("legitimate file was pruned: %s; saw %v", filepath.Join(d, ".mcp.json"), seen)
		}
	}
}

// TestWalkDoesNotDescendDirectorySymlinks verifies the walker never
// crosses into an unrelated subtree by indirection: a symlink that
// points at a directory is surfaced but not descended.
func TestWalkDoesNotDescendDirectorySymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	mustMkdir(t, target)
	mustWrite(t, filepath.Join(target, "package-lock.json"), "{}")

	linkParent := filepath.Join(root, "proj")
	mustMkdir(t, linkParent)
	link := filepath.Join(linkParent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	var c pathCollector
	if err := Walk(Options{Roots: []string{root}}, c.all); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	seen := c.seen()
	for _, p := range seen {
		if strings.HasPrefix(p, link+string(filepath.Separator)) {
			t.Errorf("walker descended a directory symlink: %s", p)
		}
	}
	// The real target is still reached by its own path.
	want := filepath.Join(target, "package-lock.json")
	found := false
	for _, p := range seen {
		if p == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to visit %q through its real path; saw %v", want, seen)
	}
}

// TestWalkParallelMatchesSerialOnOverlappingRoots pins the inode dedup
// that makes the two traversals agree. A root nested inside another root
// is a real configuration — `beagle roots` resolves both `~/.cursor` and
// `~/.cursor/extensions` — and without the shared seen map the parallel
// walker visits the inner tree twice, inflating files_considered in the
// emitted summary even though the emitter dedups the records themselves.
func TestWalkParallelMatchesSerialOnOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "nested")
	mustMkdir(t, inner)
	for i := 0; i < 5; i++ {
		dir := filepath.Join(inner, fmt.Sprintf("d%02d", i))
		mustMkdir(t, dir)
		mustWrite(t, filepath.Join(dir, "package-lock.json"), "{}")
	}

	// Both roots are walked, but the nested one is already in seen by the
	// time the second root starts, so the entry count matches a single
	// traversal of the outer root.
	var overlapping pathCollector
	if err := Walk(Options{Roots: []string{root, inner}}, overlapping.all); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	var single pathCollector
	if err := Walk(Options{Roots: []string{root}}, single.all); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got, want := len(overlapping.seen()), len(single.seen()); got != want {
		t.Fatalf("overlapping roots visited %d entries, outer root alone visits %d", got, want)
	}
}

// TestWalkIgnoresErrSkipOnAFile pins the refusal that keeps the two
// traversals in agreement. filepath.WalkDir treats a file-level ErrSkip
// as "abandon the rest of this directory"; fastwalk abandons only what
// it has not dispatched yet, which loses a non-deterministic set of
// sibling subtrees. Neither meaning is worth having, so the walker
// ignores the return, reports it through OnError, and keeps going.
func TestWalkIgnoresErrSkipOnAFile(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 12; i++ {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", i))
		mustMkdir(t, dir)
		mustWrite(t, filepath.Join(dir, "package-lock.json"), "{}")
	}
	// A file directly under root, so the skip lands in the directory
	// whose remaining entries are the 12 subtrees.
	mustWrite(t, filepath.Join(root, "trigger.txt"), "x")

	var baseline pathCollector
	if err := Walk(Options{Roots: []string{root}}, baseline.all); err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// Repeat: under the parallel walker the truncation this guards
	// against is a scheduling race, so one lucky run proves nothing.
	for i := 0; i < 25; i++ {
		var c pathCollector
		var errMu sync.Mutex
		var reported []error
		err := Walk(Options{
			Roots: []string{root},
			OnError: func(_ string, err error) {
				errMu.Lock()
				reported = append(reported, err)
				errMu.Unlock()
			},
		}, func(path string, d fs.DirEntry) error {
			if err := c.all(path, d); err != nil {
				return err
			}
			if filepath.Base(path) == "trigger.txt" {
				return ErrSkip
			}
			return nil
		})
		if err != nil {
			t.Fatalf("run %d: Walk returned %v; an ignored ErrSkip is not a walk failure", i, err)
		}
		if got, want := len(c.seen()), len(baseline.seen()); got != want {
			t.Fatalf("run %d: ErrSkip on a file truncated the walk: visited %d, want %d", i, got, want)
		}
		if len(reported) != 1 || !errors.Is(reported[0], errSkipDirOnFile) {
			t.Fatalf("run %d: want one errSkipDirOnFile through OnError, got %v", i, reported)
		}
	}
}

// TestWalkErrStopEndsEveryRoot pins ErrStop as the replacement for the
// file-level skip the walker now refuses: it stops the walk in progress
// and the roots behind it, and reports success, because a cancelled scan
// is a decision rather than a failure.
func TestWalkErrStopEndsEveryRoot(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a")
	second := filepath.Join(root, "b")
	for _, d := range []string{first, second} {
		for i := 0; i < 10; i++ {
			sub := filepath.Join(d, fmt.Sprintf("d%02d", i))
			mustMkdir(t, sub)
			mustWrite(t, filepath.Join(sub, "package-lock.json"), "{}")
		}
	}

	var c pathCollector
	var reported int
	var errMu sync.Mutex
	err := Walk(Options{
		Roots: []string{first, second},
		OnError: func(string, error) {
			errMu.Lock()
			reported++
			errMu.Unlock()
		},
	}, func(path string, d fs.DirEntry) error {
		return onlyErrStop(&c, path, d)
	})
	if err != nil {
		t.Fatalf("Walk returned %v; ErrStop is a clean stop", err)
	}
	if reported != 0 {
		t.Errorf("ErrStop was reported through OnError %d times; it is not an error", reported)
	}
	for _, p := range c.seen() {
		if strings.HasPrefix(p, second+string(filepath.Separator)) {
			t.Fatalf("ErrStop during the first root did not stop the second: visited %s", p)
		}
	}
}

// onlyErrStop records the path, then stops the walk once anything below
// the first root has been reached.
func onlyErrStop(c *pathCollector, path string, d fs.DirEntry) error {
	if err := c.all(path, d); err != nil {
		return err
	}
	if !d.IsDir() {
		return ErrStop
	}
	return nil
}

// TestIsExcludedMatching pins the matching rules the pre-separated
// exclude sets have to preserve: bare names match a basename at any
// depth, multi-component excludes match only on whole path components,
// and excludes are cleaned once rather than per call.
func TestIsExcludedMatching(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	ex := normalizeExcludes([]string{"  .git  ", "Library/Caches/", ".git", "", "a/b"})

	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/code/.git", true},
		{"/home/u/Library/Caches", true},
		{"/Library/Caches", true},
		// Component boundaries are respected: a longer name ending in
		// the excluded component is not a match.
		{"/home/u/MyLibrary/Caches", false},
		{"/home/u/code/.gitignore", false},
		{"/home/u/Caches", false},
		{"/home/u/x/a/b", true},
		{"/home/u/x/za/b", false},
	}
	for _, c := range cases {
		if got := isExcluded(c.path, filepath.Base(c.path), ex); got != c.want {
			t.Errorf("isExcluded(%q) = %v, want %v", c.path, got, c.want)
		}
	}
	if len(ex.suffix) != 2 {
		t.Errorf("suffix excludes = %v, want the two multi-component entries deduped", ex.suffix)
	}
	if _, ok := ex.bare[".git"]; !ok || len(ex.bare) != 1 {
		t.Errorf("bare excludes = %v, want just .git", ex.bare)
	}
}

// pathCollector accumulates the paths a Visitor is handed. Walk drives
// the visitor from a pool of goroutines in the default build, so no test
// may append to a bare slice from inside one.
type pathCollector struct {
	mu    sync.Mutex
	paths []string
}

func (c *pathCollector) all(path string, d fs.DirEntry) error {
	c.mu.Lock()
	c.paths = append(c.paths, path)
	c.mu.Unlock()
	return nil
}

func (c *pathCollector) files(path string, d fs.DirEntry) error {
	if d.IsDir() {
		return nil
	}
	return c.all(path, d)
}

func (c *pathCollector) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.paths...)
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

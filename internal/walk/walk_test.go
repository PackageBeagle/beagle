package walk

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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

	var seen []string
	err := Walk(Options{
		Roots:    []string{root},
		Excludes: excludes,
	}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			seen = append(seen, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
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

	var seen []string
	err := Walk(Options{
		Roots:    []string{root},
		Excludes: append([]string{}, DefaultExcludes...),
	}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			seen = append(seen, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

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

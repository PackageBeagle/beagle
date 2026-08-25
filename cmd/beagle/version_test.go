package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fileDefaultRe matches the compiled-in version fallback in either
// version.go. The constant is function-local in both files and the
// osquery module cannot be imported from here, so the check reads the
// source rather than the symbol.
var fileDefaultRe = regexp.MustCompile(`(?m)^\s*const fileDefault = "([^"]*)"\s*$`)

// semverRe is deliberately strict: VERSION carries a bare X.Y.Z with no
// leading "v", which is what both fileDefault constants must equal.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// TestVersionConstantsMatchVERSIONFile pins the one piece of duplicated
// state in this repo that nothing else verifies. VERSION,
// cmd/beagle's fileDefault, and osquery's fileDefault all have to agree,
// and none of the three reads the others: the osquery module has no
// require on the core, and neither constant reads the file at build
// time.
//
// It matters more than a normal duplication because of how releases
// work. A v* tag drives goreleaser directly, and the protect-tags
// ruleset makes v* tags immutable — no delete, update, or force-push. So
// a release cut while one of these three is stale cannot be corrected in
// place; the only recovery is bumping all three again and burning the
// next patch number. This test turns that into a failing check on the
// pull request that would have introduced it.
func TestVersionConstantsMatchVERSIONFile(t *testing.T) {
	root := filepath.Join("..", "..")

	want := readVersionFile(t, filepath.Join(root, "VERSION"))
	if !semverRe.MatchString(want) {
		t.Fatalf("VERSION contains %q, want a bare X.Y.Z with no leading \"v\"", want)
	}

	for _, rel := range []string{
		filepath.Join("cmd", "beagle", "version.go"),
		filepath.Join("osquery", "version.go"),
	} {
		if got := readFileDefault(t, root, rel); got != want {
			t.Errorf("%s has fileDefault = %q, but VERSION says %q\n"+
				"all three must be bumped together; see docs/DESIGN.md, \"Core invariants\"", rel, got, want)
		}
	}
}

func readVersionFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading VERSION: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// readFileDefault extracts the fileDefault constant from a version.go.
// A missing or duplicated match fails rather than being skipped: this
// check is worthless if it can silently verify nothing, which is exactly
// what would happen if someone reformatted the declaration.
func readFileDefault(t *testing.T, root, rel string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	m := fileDefaultRe.FindAllStringSubmatch(string(b), -1)
	if len(m) != 1 {
		t.Fatalf("found %d `const fileDefault = \"...\"` declarations in %s, want exactly 1; "+
			"the version guard cannot verify what it cannot find", len(m), rel)
	}
	return m[0][1]
}

package yarn

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestNameFromYarnHeader(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"lodash@^4.17.0"`, "lodash"},
		{`lodash@^4.17.0`, "lodash"},
		{`"@scope/pkg@^1.0.0"`, "@scope/pkg"},
		{`"@scope/pkg@^1.0.0, @scope/pkg@^1.1.0"`, "@scope/pkg"},
		{`"lodash@npm:^4.17.0"`, "lodash"},
		{`"@tanstack/query-core@npm:5.0.0"`, "@tanstack/query-core"},
		// Berry spec with an embedded comma in the version range. The
		// descriptor list separator is ", " (comma+space), so a bare
		// comma inside the spec must not truncate the descriptor.
		{`"foo@npm:>=1, <2"`, "foo"},
	}
	for _, c := range cases {
		if g := nameFromYarnHeader(c.in); g != c.want {
			t.Errorf("nameFromYarnHeader(%q) = %q, want %q", c.in, g, c.want)
		}
	}
}

func TestScanLockfile_Classic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	body := `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-xyz

"@tanstack/query-core@^5.0.0":
  version "5.0.0"
  resolved "https://registry.yarnpkg.com/@tanstack/query-core/-/query-core-5.0.0.tgz"
  integrity sha512-tan

chalk@^5.0.0, chalk@^5.3.0:
  version "5.3.0"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-5.3.0.tgz"
  integrity sha512-chalk
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "@tanstack/query-core" || out[0].Version != "5.0.0" {
		t.Errorf("first: %+v", out[0])
	}
	if out[1].PackageName != "chalk" || out[1].Version != "5.3.0" {
		t.Errorf("chalk: %+v", out[1])
	}
	if out[2].PackageName != "lodash" || out[2].Version != "4.17.21" {
		t.Errorf("lodash: %+v", out[2])
	}
}

// TestLoadDirectDeps exercises loadDirectDeps directly (rather than through
// Scanner.ScanLockfile) to pin down the boundary and diag behavior of the
// fsread.Bounded-based read: exactly-at-limit still succeeds, one byte over
// produces exactly one warn diag (fsread.Bounded's own too-large warning,
// not a second one from loadDirectDeps), missing files stay silent, and
// parse failures still warn.
func TestLoadDirectDeps(t *testing.T) {
	body := []byte(`{"dependencies":{"lodash":"^4"},"devDependencies":{"chalk":"^5"}}`)

	t.Run("exactly at max size returns deps", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		var diags []string
		deps := loadDirectDeps(path, int64(len(body)), func(level, p, msg string) {
			diags = append(diags, level+":"+msg)
		})
		if deps == nil {
			t.Fatal("expected non-nil deps")
		}
		if !deps["lodash"] || !deps["chalk"] {
			t.Errorf("deps = %v, want lodash and chalk", deps)
		}
		if len(diags) != 0 {
			t.Errorf("expected no diags, got %v", diags)
		}
	})

	t.Run("over max size returns nil with exactly one warn diag", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		var diags []string
		deps := loadDirectDeps(path, int64(len(body))-1, func(level, p, msg string) {
			diags = append(diags, level+":"+msg)
		})
		if deps != nil {
			t.Errorf("expected nil deps, got %v", deps)
		}
		if len(diags) != 1 {
			t.Fatalf("expected exactly one diag, got %d: %v", len(diags), diags)
		}
		if !strings.HasPrefix(diags[0], "warn:") {
			t.Errorf("expected warn diag, got %q", diags[0])
		}
	})

	t.Run("missing file returns nil with no diag", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		var diags []string
		deps := loadDirectDeps(path, 1<<20, func(level, p, msg string) {
			diags = append(diags, level+":"+msg)
		})
		if deps != nil {
			t.Errorf("expected nil deps, got %v", deps)
		}
		if len(diags) != 0 {
			t.Errorf("expected no diags, got %v", diags)
		}
	})

	t.Run("unparseable JSON returns nil with warn diag", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "package.json")
		if err := os.WriteFile(path, []byte(`{not valid`), 0o644); err != nil {
			t.Fatal(err)
		}
		var diags []string
		deps := loadDirectDeps(path, 1<<20, func(level, p, msg string) {
			diags = append(diags, level+":"+msg)
		})
		if deps != nil {
			t.Errorf("expected nil deps, got %v", deps)
		}
		if len(diags) != 1 || !strings.HasPrefix(diags[0], "warn:") {
			t.Fatalf("expected exactly one warn diag, got %v", diags)
		}
	})
}

func TestScanLockfile_DirectFromPackageJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
  "name": "demo",
  "dependencies": {"lodash": "^4.17.0"},
  "devDependencies": {"chalk": "^5.0.0"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "yarn.lock")
	body := `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"

chalk@^5.0.0:
  version "5.3.0"

ms@^2.0.0:
  version "2.1.3"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	expect := map[string]bool{
		"chalk":  true,
		"lodash": true,
		"ms":     false,
	}
	for _, r := range out {
		want, ok := expect[r.PackageName]
		if !ok {
			t.Fatalf("unexpected pkg %q", r.PackageName)
		}
		if r.DirectDependency == nil {
			t.Errorf("%s: DirectDependency=nil, want %v", r.PackageName, want)
			continue
		}
		if *r.DirectDependency != want {
			t.Errorf("%s: DirectDependency=%v, want %v", r.PackageName, *r.DirectDependency, want)
		}
	}
}

func TestScanLockfile_NoPackageJSONLeavesDirectUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	body := `lodash@^4.17.0:
  version "4.17.21"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].DirectDependency != nil {
		t.Errorf("expected DirectDependency nil, got %v", *out[0].DirectDependency)
	}
}

// TestScanLockfile_MalformedPackageJSONEmitsDiag verifies that an
// unparseable sibling package.json surfaces a warn diagnostic rather
// than silently leaving DirectDependency unset. A missing package.json
// remains silent — that is the common case.
func TestScanLockfile_MalformedPackageJSONEmitsDiag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{not valid`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "yarn.lock")
	body := `lodash@^4.17.0:
  version "4.17.21"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	type diag struct{ level, path, msg string }
	var diags []diag
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) {},
		Diag:        func(level, p, msg string) { diags = append(diags, diag{level, p, msg}) },
	}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range diags {
		if d.level == "warn" && d.path == filepath.Join(dir, "package.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected warn diag for malformed package.json, got %+v", diags)
	}
}

func TestScanLockfile_Berry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	body := `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10/abc
  languageName: node
  linkType: hard
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageName != "lodash" || out[0].Version != "4.17.21" {
		t.Errorf("lodash: %+v", out[0])
	}
}

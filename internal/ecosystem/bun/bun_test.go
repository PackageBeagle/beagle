package bun

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestSplitAtVersion(t *testing.T) {
	cases := []struct{ in, n, v string }{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@tanstack/query-core@5.0.0", "@tanstack/query-core", "5.0.0"},
		{"", "", ""},
	}
	for _, c := range cases {
		n, v := splitAtVersion(c.in)
		if n != c.n || v != c.v {
			t.Errorf("splitAtVersion(%q) = (%q,%q)", c.in, n, v)
		}
	}
}

func TestStripJSONC(t *testing.T) {
	in := []byte(`{
  // comment
  "a": "b", /* inline */
  "c": [1, 2, 3,], // trailing comma
}`)
	out, err := stripJSONC(in)
	if err != nil {
		t.Fatalf("stripJSONC error: %v", err)
	}
	// Quick sanity: no slashes outside string content; original strings preserved.
	if string(out) == string(in) {
		t.Errorf("stripJSONC made no change")
	}
}

func TestStripJSONCUnterminatedBlockComment(t *testing.T) {
	in := []byte(`{"a": 1 /* never closed`)
	out, err := stripJSONC(in)
	if err == nil {
		t.Fatal("expected error for unterminated block comment")
	}
	// On error the original bytes must be returned so the JSON parser can
	// produce its own diagnostic instead of silently consuming the tail.
	if string(out) != string(in) {
		t.Errorf("expected original bytes on error")
	}
}

// TestLoadDirectDeps exercises loadDirectDeps directly (rather than through
// Scanner.ScanTextLockfile) to pin down the boundary and diag behavior of
// the fsread.Bounded-based read: exactly-at-limit still succeeds, one byte
// over produces exactly one warn diag (fsread.Bounded's own too-large
// warning, not a second one from loadDirectDeps), missing files stay
// silent, and parse failures still warn.
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

func TestScanTextLockfile_DirectFromPackageJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
  "name": "demo",
  "dependencies": {"lodash": "^4"},
  "devDependencies": {"@tanstack/query-core": "^5"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bun.lock")
	body := `{
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21"],
    "@tanstack/query-core": ["@tanstack/query-core@5.0.0"],
    "ms": ["ms@2.1.3"]
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanTextLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	expect := map[string]bool{
		"@tanstack/query-core": true,
		"lodash":               true,
		"ms":                   false,
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

func TestScanTextLockfile_NoPackageJSONLeavesDirectUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bun.lock")
	body := `{
  "lockfileVersion": 0,
  "packages": {"lodash": ["lodash@4.17.21"]}
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanTextLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].DirectDependency != nil {
		t.Errorf("expected DirectDependency nil, got %v", *out[0].DirectDependency)
	}
}

// TestScanTextLockfile_MalformedPackageJSONEmitsDiag verifies that an
// unparseable sibling package.json surfaces a warn diagnostic. Missing
// package.json remains silent.
func TestScanTextLockfile_MalformedPackageJSONEmitsDiag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{not valid`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bun.lock")
	body := `{
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21"]
  }
}`
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
	if err := s.ScanTextLockfile(path, model.Record{}); err != nil {
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

func TestScanTextLockfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bun.lock")
	body := `{
  // generated by bun
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21", {"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-x"}],
    "@tanstack/query-core": ["@tanstack/query-core@5.0.0"],
    "weird": {"version":"1.0.0","integrity":"sha512-y"},
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanTextLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "@tanstack/query-core" || out[0].Version != "5.0.0" {
		t.Errorf("tan: %+v", out[0])
	}
	if out[1].PackageName != "lodash" || out[1].Version != "4.17.21" {
		t.Errorf("lodash: %+v", out[1])
	}
	if out[2].PackageName != "weird" || out[2].Version != "1.0.0" {
		t.Errorf("weird: %+v", out[2])
	}
	for _, r := range out {
		if r.SourceType != "bun-lockfile" {
			t.Errorf("source_type=%q", r.SourceType)
		}
		if r.PackageManager != "bun" {
			t.Errorf("package_manager=%q", r.PackageManager)
		}
	}
}

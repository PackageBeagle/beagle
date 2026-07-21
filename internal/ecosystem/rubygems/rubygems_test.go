package rubygems

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestParseGemfileLock(t *testing.T) {
	body := `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)
    rails (7.1.2)
      actionpack (= 7.1.2)
    actionpack (7.1.2)
      rack (>= 2.2.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.0
`
	gems := parseGemfileLock([]byte(body))
	if len(gems) != 3 {
		t.Fatalf("want 3, got %d: %+v", len(gems), gems)
	}
	got := map[string]string{}
	for _, g := range gems {
		got[g.name] = g.version
	}
	if got["rack"] != "3.0.8" || got["rails"] != "7.1.2" || got["actionpack"] != "7.1.2" {
		t.Errorf("got %+v", got)
	}
}

func TestScanGemfileLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Gemfile.lock")
	body := `GEM
  remote: https://rubygems.org/
  specs:
    intercom-rails (0.4.3)
    rails (7.1.2)
      actionpack (= 7.1.2)

PLATFORMS
  ruby

DEPENDENCIES
  rails
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGemfileLock(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d", len(out))
	}
	if out[0].PackageName != "intercom-rails" || out[0].Version != "0.4.3" {
		t.Errorf("intercom-rails: %+v", out[0])
	}
	if out[1].PackageName != "rails" || out[1].Version != "7.1.2" {
		t.Errorf("rails: %+v", out[1])
	}
}

func TestScanGemspec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intercom-rails-0.4.3.gemspec")
	body := `# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name = "intercom-rails"
  s.version = "0.4.3"
  s.authors = ["Someone"]
end
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGemspec(path, filepath.Dir(path), model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageName != "intercom-rails" || out[0].Version != "0.4.3" {
		t.Errorf("got %+v", out[0])
	}
	if out[0].SourceType != "rubygems-gemspec" || out[0].Confidence != "medium" {
		t.Errorf("source/confidence: %+v", out[0])
	}
}

func TestIsInstalledGemspec(t *testing.T) {
	ok, _ := IsInstalledGemspec("/x/gems/3.2.0/specifications/intercom-rails-0.4.3.gemspec")
	if !ok {
		t.Errorf("specifications path should match")
	}
	ok, _ = IsInstalledGemspec("/x/gems/3.2.0/gems/intercom-rails-0.4.3/intercom-rails.gemspec")
	if !ok {
		t.Errorf("installed gem dir gemspec should match")
	}
	// Arbitrary vendored gem sources should NOT match: there's no recognizable
	// installed-gems root above the `gems/` directory.
	if ok, _ := IsInstalledGemspec("/home/user/proj/gems/foo-1.0/foo.gemspec"); ok {
		t.Errorf("arbitrary vendored gem source should not be treated as installed metadata")
	}
	// Mismatched filename vs parent dir name should NOT match (sloppy vendoring).
	if ok, _ := IsInstalledGemspec("/x/gems/3.2.0/gems/intercom-rails-0.4.3/other.gemspec"); ok {
		t.Errorf("filename/parent-dir mismatch should not be treated as installed metadata")
	}
}

func TestGemspecVersionRegex(t *testing.T) {
	// Canonical generated form in specifications/<name>-<ver>.gemspec.
	body := []byte(`Gem::Specification.new do |s|
  s.name = "intercom-rails"
  s.version = Gem::Version.new("0.4.3")
end
`)
	if v := firstSubmatch(gemspecVersionRe, body); v != "0.4.3" {
		t.Errorf("Gem::Version.new form: got %q want 0.4.3", v)
	}
	// Plain string form also still matches.
	body2 := []byte(`s.version = '1.2.3'`)
	if v := firstSubmatch(gemspecVersionRe, body2); v != "1.2.3" {
		t.Errorf("plain string form: got %q want 1.2.3", v)
	}
}

package composer

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestScanComposerLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "composer.lock")
	body := `{
  "_readme": [],
  "packages": [
    {"name":"intercom/intercom-php","version":"5.0.2","type":"library","dist":{"url":"https://api.github.com/repos/intercom/intercom-php/zipball/abc","shasum":"deadbeef"}},
    {"name":"monolog/monolog","version":"3.5.0","dist":{"url":"https://example/m.zip"}}
  ],
  "packages-dev": [
    {"name":"phpunit/phpunit","version":"10.5.0"}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanComposerLock(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d", len(out))
	}
	if out[0].PackageName != "intercom/intercom-php" || out[0].Version != "5.0.2" {
		t.Errorf("intercom: %+v", out[0])
	}
	if out[0].InstallScope != "prod" || out[2].InstallScope != "dev" {
		t.Errorf("scopes: prod=%q dev=%q", out[0].InstallScope, out[2].InstallScope)
	}
	if out[2].PackageName != "phpunit/phpunit" {
		t.Errorf("phpunit ordering")
	}
}

func TestScanInstalledJSON_V2(t *testing.T) {
	dir := t.TempDir()
	vendorComposer := filepath.Join(dir, "vendor", "composer")
	if err := os.MkdirAll(vendorComposer, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vendorComposer, "installed.json")
	body := `{"packages":[{"name":"intercom/intercom-php","version":"5.0.2"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if !IsInstalledJSON(path) {
		t.Fatalf("IsInstalledJSON should be true for %q", path)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanInstalledJSON(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PackageName != "intercom/intercom-php" {
		t.Fatalf("got %+v", out)
	}
	if out[0].SourceType != "composer-installed" || out[0].Confidence != "medium" {
		t.Errorf("metadata: %+v", out[0])
	}
}

// TestScanInstalledJSON_V2Empty verifies that an empty v2 installed.json
// ({"packages": []}) parses cleanly and emits no records, rather than
// falling through to a v1 (root array) parse error.
func TestScanInstalledJSON_V2Empty(t *testing.T) {
	dir := t.TempDir()
	vendorComposer := filepath.Join(dir, "vendor", "composer")
	if err := os.MkdirAll(vendorComposer, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vendorComposer, "installed.json")
	if err := os.WriteFile(path, []byte(`{"packages":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanInstalledJSON(path, model.Record{}); err != nil {
		t.Fatalf("expected empty v2 envelope to parse, got error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected zero records, got %d", len(out))
	}
}

func TestScanInstalledJSON_V1Array(t *testing.T) {
	dir := t.TempDir()
	vendorComposer := filepath.Join(dir, "vendor", "composer")
	if err := os.MkdirAll(vendorComposer, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vendorComposer, "installed.json")
	body := `[{"name":"monolog/monolog","version":"2.0.0"}]`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanInstalledJSON(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PackageName != "monolog/monolog" {
		t.Fatalf("got %+v", out)
	}
}

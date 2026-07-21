package pypi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newCollector() (*Scanner, *[]model.Record) {
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 5 * 1024 * 1024,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) {},
	}
	return s, &got
}

func TestScanDistInfoWithDirectURLAndInstaller(t *testing.T) {
	dir := t.TempDir()
	di := filepath.Join(dir, "site-packages", "Flask-3.0.0.dist-info")
	writeFile(t, filepath.Join(di, "METADATA"), `Metadata-Version: 2.1
Name: Flask
Version: 3.0.0
Summary: A simple framework
Author-email: someone@example.com

This is the long description.
Name: NotAName
Version: 9.9.9
`)
	writeFile(t, filepath.Join(di, "INSTALLER"), "pip\n")
	writeFile(t, filepath.Join(di, "direct_url.json"), `{"url":"https://files.pythonhosted.org/x.whl","archive_info":{}}`)

	ok, distDir := IsDistInfoMetadata(filepath.Join(di, "METADATA"))
	if !ok || distDir != di {
		t.Fatalf("IsDistInfoMetadata failed: %v %q", ok, distDir)
	}
	s, got := newCollector()
	if err := s.ScanDistInfo(filepath.Join(di, "METADATA"), di, model.Record{}); err != nil {
		t.Fatalf("ScanDistInfo: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(*got))
	}
	r := (*got)[0]
	if r.PackageName != "Flask" || r.NormalizedName != "flask" {
		t.Errorf("name/normalized = %q/%q", r.PackageName, r.NormalizedName)
	}
	if r.Version != "3.0.0" {
		t.Errorf("version = %q", r.Version)
	}
	if r.PackageManager != "pip" {
		t.Errorf("package_manager = %q", r.PackageManager)
	}
	if r.DirectDependency == nil || !*r.DirectDependency {
		t.Errorf("expected direct=true from direct_url.json")
	}
}

func TestScanEggInfo(t *testing.T) {
	dir := t.TempDir()
	eg := filepath.Join(dir, "site-packages", "Old-1.2.egg-info")
	writeFile(t, filepath.Join(eg, "PKG-INFO"), `Metadata-Version: 1.0
Name: Old_Package.Name
Version: 1.2

`)
	ok, ed := IsEggInfoPKGInfo(filepath.Join(eg, "PKG-INFO"))
	if !ok || ed != eg {
		t.Fatalf("IsEggInfoPKGInfo failed: %v %q", ok, ed)
	}
	s, got := newCollector()
	if err := s.ScanEggInfo(filepath.Join(eg, "PKG-INFO"), eg, model.Record{}); err != nil {
		t.Fatalf("ScanEggInfo: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(*got))
	}
	r := (*got)[0]
	if r.NormalizedName != "old-package-name" {
		t.Errorf("normalized = %q", r.NormalizedName)
	}
	if r.SourceType != "pypi-egg-info" {
		t.Errorf("source_type = %q", r.SourceType)
	}
}

func TestMalformedMetadata(t *testing.T) {
	dir := t.TempDir()
	di := filepath.Join(dir, "broken.dist-info")
	writeFile(t, filepath.Join(di, "METADATA"), "no headers here\njust junk\n")
	var diags []string
	s := &Scanner{
		MaxFileSize: 5 * 1024 * 1024,
		Emit:        func(model.Record) {},
		Diag:        func(level, path, msg string) { diags = append(diags, level+":"+msg) },
	}
	if err := s.ScanDistInfo(filepath.Join(di, "METADATA"), di, model.Record{}); err != nil {
		t.Fatalf("incomplete METADATA should be a warn diagnostic, not an error: %v", err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], "warn:") {
		t.Fatalf("expected one warn diagnostic, got %v", diags)
	}
}

func TestMalformedPKGInfo(t *testing.T) {
	dir := t.TempDir()
	eg := filepath.Join(dir, "broken.egg-info")
	writeFile(t, filepath.Join(eg, "PKG-INFO"), "no headers\n")
	var diags []string
	s := &Scanner{
		MaxFileSize: 5 * 1024 * 1024,
		Emit:        func(model.Record) {},
		Diag:        func(level, path, msg string) { diags = append(diags, level+":"+msg) },
	}
	if err := s.ScanEggInfo(filepath.Join(eg, "PKG-INFO"), eg, model.Record{}); err != nil {
		t.Fatalf("incomplete PKG-INFO should be a warn diagnostic, not an error: %v", err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], "warn:") {
		t.Fatalf("expected one warn diagnostic, got %v", diags)
	}
}

func TestMaxFileSizeSkip(t *testing.T) {
	dir := t.TempDir()
	di := filepath.Join(dir, "big.dist-info")
	writeFile(t, filepath.Join(di, "METADATA"), "Name: big\nVersion: 1\n\n")
	s, _ := newCollector()
	s.MaxFileSize = 2
	if err := s.ScanDistInfo(filepath.Join(di, "METADATA"), di, model.Record{}); err == nil {
		t.Fatal("expected size error")
	}
}

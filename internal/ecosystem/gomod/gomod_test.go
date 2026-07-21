package gomod

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestScanGoSum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	body := `github.com/example/foo v1.2.3 h1:abc=
github.com/example/foo v1.2.3/go.mod h1:def=
github.com/example/bar v0.0.0-20240101000000-abcdef h1:bar=
github.com/example/bar v0.0.0-20240101000000-abcdef/go.mod h1:bar2=
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGoSum(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(out), out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "github.com/example/bar" || out[0].Version != "v0.0.0-20240101000000-abcdef" {
		t.Errorf("bar: %+v", out[0])
	}
	if out[1].PackageName != "github.com/example/foo" || out[1].Version != "v1.2.3" {
		t.Errorf("foo: %+v", out[1])
	}
	for _, r := range out {
		if r.SourceType != "go-sum" {
			t.Errorf("source_type=%q", r.SourceType)
		}
		if r.Ecosystem != "go" {
			t.Errorf("ecosystem=%q", r.Ecosystem)
		}
	}
}

func TestScanGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	body := `module example.com/x

go 1.22

require github.com/example/single v1.0.0

require (
	github.com/example/foo v1.2.3
	github.com/example/bar v0.0.0-20240101000000-abcdef // indirect
)
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGoMod(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "github.com/example/bar" || out[0].InstallScope != "indirect" {
		t.Errorf("bar: %+v", out[0])
	}
	if out[0].DirectDependency == nil || *out[0].DirectDependency {
		t.Errorf("bar should be indirect")
	}
	if out[1].PackageName != "github.com/example/foo" || out[1].InstallScope == "indirect" {
		t.Errorf("foo: %+v", out[1])
	}
	if out[2].PackageName != "github.com/example/single" {
		t.Errorf("single: %+v", out[2])
	}
}

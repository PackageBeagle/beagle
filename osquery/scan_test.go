package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/packagebeagle/beagle/internal/model"
)

func fixturesDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "cmd", "beagle", "selftest", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("selftest fixtures not found: %v", err)
	}
	return abs
}

func testBridge() *scanBridge {
	return newScanBridge(bridgeConfig{
		MaxDurationOverride: 30 * time.Second,
		CacheTTL:            time.Minute,
		Diags:               io.Discard,
	})
}

func TestBridgeScanFixtures(t *testing.T) {
	b := testBridge()
	out, err := b.Scan(context.Background(), model.ProfileBaseline, []string{fixturesDir(t)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) == 0 {
		t.Fatal("no records from fixtures tree")
	}
	if out.Truncated {
		t.Fatal("fixtures scan reported truncated")
	}
	if len(out.Roots) != 1 {
		t.Fatalf("resolved roots = %v, want the single explicit root", out.Roots)
	}
	for _, r := range out.Records {
		if r.RecordType != model.RecordTypePackage {
			t.Fatalf("record_type = %q, want package", r.RecordType)
		}
		if r.ScanTime == "" {
			t.Fatal("scan_time is empty; bridge must set BaseRecord.ScanTime")
		}
		if r.ScannerName != model.ScannerName {
			t.Fatalf("scanner_name = %q", r.ScannerName)
		}
		if r.RunID == "" || r.SchemaVersion == "" || r.ScannerVersion == "" {
			t.Fatalf("missing identity fields on record: %+v", r)
		}
		if r.Profile != model.ProfileBaseline {
			t.Fatalf("profile = %q, want baseline", r.Profile)
		}
	}
}

func TestBridgeUnknownProfile(t *testing.T) {
	_, err := testBridge().Scan(context.Background(), "bogus", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("err = %v, want unknown-profile error from roots.Resolve", err)
	}
}

func TestBridgeDeepRequiresExplicitRoot(t *testing.T) {
	_, err := testBridge().Scan(context.Background(), model.ProfileDeep, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires at least one explicit root") {
		t.Fatalf("err = %v, want deep-requires-root error", err)
	}
}

func TestBridgeBroadHomeRootRefused(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	_, err = testBridge().Scan(context.Background(), model.ProfileBaseline, []string{home}, nil)
	if err == nil || !strings.Contains(err.Error(), "--profile deep") {
		t.Fatalf("err = %v, want broad-home-root guardrail error", err)
	}
}

func TestScanBudget(t *testing.T) {
	cases := []struct {
		name     string
		profile  string
		override time.Duration
		want     time.Duration
	}{
		{"baseline default", model.ProfileBaseline, 0, 120 * time.Second},
		{"project default", model.ProfileProject, 0, 300 * time.Second},
		{"deep default", model.ProfileDeep, 0, 300 * time.Second},
		{"unknown profile falls back to baseline default", "bogus", 0, 120 * time.Second},
		{"override wins over baseline", model.ProfileBaseline, 5 * time.Second, 5 * time.Second},
		{"override wins over deep", model.ProfileDeep, 5 * time.Second, 5 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanBudget(c.profile, c.override); got != c.want {
				t.Fatalf("scanBudget(%q, %v) = %v, want %v", c.profile, c.override, got, c.want)
			}
		})
	}
}

func TestCacheKeyOrderInsensitive(t *testing.T) {
	if cacheKey("baseline", []string{"/a", "/b"}, nil) != cacheKey("baseline", []string{"/b", "/a"}, nil) {
		t.Fatal("cache key must not depend on root order")
	}
	if cacheKey("baseline", []string{"/a"}, nil) == cacheKey("deep", []string{"/a"}, nil) {
		t.Fatal("cache key must include profile")
	}
	if cacheKey("baseline", nil, nil) == cacheKey("baseline", []string{""}, nil) {
		// Never delivered by osquery (verified), but the key must still
		// be injective if that changes.
		t.Fatal("cache key must distinguish no roots from one empty root")
	}
}

func TestCacheKeyIncludesExcludes(t *testing.T) {
	roots := []string{"/Users/"}
	if cacheKey("deep", roots, nil) == cacheKey("deep", roots, []string{"/Users/*/scripts"}) {
		t.Fatal("cache key must include the exclude patterns")
	}
	if cacheKey("deep", roots, []string{"/Users/*/a", "/Users/*/b"}) !=
		cacheKey("deep", roots, []string{"/Users/*/b", "/Users/*/a"}) {
		t.Fatal("cache key must not depend on exclude order")
	}
	// An exclude must not be confusable with a root.
	if cacheKey("deep", nil, []string{"/a"}) == cacheKey("deep", []string{"/a"}, nil) {
		t.Fatal("cache key must distinguish an exclude from a root")
	}
}

func TestBridgeScanAppliesExcludes(t *testing.T) {
	fixtures := fixturesDir(t)
	b := testBridge()
	full, err := b.Scan(context.Background(), model.ProfileDeep, []string{fixtures}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The root is inside the second pattern's tree, so nothing is scanned.
	excludes := []string{"/nonexistent", fixtures}
	none, err := b.Scan(context.Background(), model.ProfileDeep, []string{fixtures}, excludes)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Records) == 0 || len(none.Records) != 0 {
		t.Fatalf("records: unexcluded=%d excluded=%d, want >0 and 0", len(full.Records), len(none.Records))
	}
}

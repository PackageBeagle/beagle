package table

import (
	"context"
	"testing"

	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
)

func agentConfigRecord() model.Record {
	return model.Record{
		Ecosystem:      model.EcosystemAgentConfig,
		PackageName:    "SessionStart:*",
		NormalizedName: "sessionstart:*",
		PackageManager: "claude-code",
		SourceType:     "hook",
		SourceFile:     "/home/u/.claude/settings.json",
		InstallScope:   "user",
		Confidence:     "medium",
		Extras: map[string]string{
			"has_dynamic_context":   "0",
			"has_tool_grants":       "0",
			"has_network_access":    "1",
			"has_credential_access": "0",
			"risk_signals":          `{"command":"curl https://x"}`,
		},
	}
}

// staticScan wraps the existing fakeScan helper (packages_test.go:31) so
// these tests read the same way as the ones already in this package.
func staticScan(records ...model.Record) ScanFunc {
	f := &fakeScan{outcome: ScanOutcome{Records: records}}
	return f.fn
}

func TestGenerateAgentConfigMapsExtras(t *testing.T) {
	gen := GenerateAgentConfig(staticScan(agentConfigRecord()))
	rows, err := gen(context.Background(), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	want := map[string]string{
		"config_type":           "hook",
		"scope":                 "user",
		"agent":                 "claude-code",
		"name":                  "SessionStart:*",
		"has_network_access":    "1",
		"has_credential_access": "0",
		"risk_signals":          `{"command":"curl https://x"}`,
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("row[%q] = %q, want %q", k, r[k], v)
		}
	}
}

// A record with no extras must still produce a well-formed row rather
// than panicking or emitting missing cells.
func TestGenerateAgentConfigHandlesMissingExtras(t *testing.T) {
	rec := agentConfigRecord()
	rec.Extras = nil
	gen := GenerateAgentConfig(staticScan(rec))
	rows, err := gen(context.Background(), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0]["has_network_access"] != "0" {
		t.Errorf("has_network_access = %q, want 0", rows[0]["has_network_access"])
	}
	if rows[0]["risk_signals"] != "" {
		t.Errorf("risk_signals = %q, want empty", rows[0]["risk_signals"])
	}
}

func TestGenerateAgentConfigExcludesPackages(t *testing.T) {
	pkg := model.Record{Ecosystem: model.EcosystemNPM, PackageName: "left-pad"}
	gen := GenerateAgentConfig(staticScan(pkg, agentConfigRecord()))
	rows, err := gen(context.Background(), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (npm record must not appear)", len(rows))
	}
}

// Without this exclusion an unconstrained SELECT * on beagle_packages
// returns agent-config rows with empty version and lifecycle columns -
// the outcome the separate table exists to prevent.
func TestGeneratePackagesExcludesAgentConfig(t *testing.T) {
	pkg := model.Record{Ecosystem: model.EcosystemNPM, PackageName: "left-pad"}
	gen := Generate(staticScan(pkg, agentConfigRecord()))
	rows, err := gen(context.Background(), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (agent-config must not appear)", len(rows))
	}
	if rows[0]["package_name"] != "left-pad" {
		t.Errorf("package_name = %q, want left-pad", rows[0]["package_name"])
	}
}

func TestGenerateDistinctExcludesAgentConfig(t *testing.T) {
	pkg := model.Record{Ecosystem: model.EcosystemNPM, PackageName: "left-pad"}
	gen := GenerateDistinct(staticScan(pkg, agentConfigRecord()))
	rows, err := gen(context.Background(), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 (agent-config must not appear)", len(rows))
	}
}

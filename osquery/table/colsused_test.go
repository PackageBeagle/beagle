package table

import (
	"context"
	"sort"
	"strings"
	"testing"

	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
)

func rowKeys(row map[string]string) []string {
	keys := make([]string, 0, len(row))
	for k := range row {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func wantKeys(t *testing.T, row map[string]string, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := rowKeys(row)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("row columns = %v, want %v", got, want)
	}
}

func TestProjectRowKeepsOnlyColsUsed(t *testing.T) {
	row := map[string]string{"a": "1", "b": "2", "c": "3"}
	projectRow(row, colsUsedSet{"a": {}, "c": {}})
	wantKeys(t, row, "a", "c")
	if row["a"] != "1" || row["c"] != "3" {
		t.Errorf("values changed: %v", row)
	}
}

// A nil set is what an osquery build that does not send colsUsed produces.
// It must mean "every column", not "no columns".
func TestProjectRowNilSetKeepsEveryColumn(t *testing.T) {
	row := map[string]string{"a": "1", "b": "2"}
	projectRow(row, nil)
	wantKeys(t, row, "a", "b")
}

// An empty (non-nil) set is a real answer, sent for a bare count(*): the
// query reads no columns, so the cheapest correct row has no cells.
func TestProjectRowEmptySetDropsEveryCell(t *testing.T) {
	row := map[string]string{"a": "1", "b": "2"}
	projectRow(row, colsUsedSet{})
	if len(row) != 0 {
		t.Errorf("row = %v, want no cells", row)
	}
}

// colsUsed can name a column the row does not carry; projection must not
// invent a cell for it.
func TestProjectRowIgnoresUnknownColumns(t *testing.T) {
	row := map[string]string{"a": "1"}
	projectRow(row, colsUsedSet{"a": {}, "nonexistent": {}})
	wantKeys(t, row, "a")
}

func TestNewColsUsedSetRoundTripsThroughContext(t *testing.T) {
	ctx := WithColsUsed(context.Background(), []string{"a", "b"})
	got := colsUsedFrom(ctx)
	if got == nil {
		t.Fatal("colsUsedFrom returned nil, want the attached set")
	}
	if _, ok := got["a"]; !ok {
		t.Errorf("set = %v, want it to contain a", got)
	}
	if _, ok := got["b"]; !ok {
		t.Errorf("set = %v, want it to contain b", got)
	}
}

func TestColsUsedFromBareContextIsNil(t *testing.T) {
	if got := colsUsedFrom(context.Background()); got != nil {
		t.Errorf("colsUsedFrom(background) = %v, want nil (no projection)", got)
	}
}

// WithColsUsed(nil) must not become "return nothing": a caller with no
// columns to report should leave the context alone instead.
func TestWithColsUsedEmptySliceIsStillEmptySet(t *testing.T) {
	ctx := WithColsUsed(context.Background(), []string{})
	got := colsUsedFrom(ctx)
	if got == nil {
		t.Fatal("colsUsedFrom returned nil, want an empty (non-nil) set")
	}
	if len(got) != 0 {
		t.Errorf("set = %v, want empty", got)
	}
}

func npmRecord(name, version, sourceFile string) model.Record {
	return model.Record{
		Ecosystem:      model.EcosystemNPM,
		PackageName:    name,
		NormalizedName: name,
		Version:        version,
		SourceFile:     sourceFile,
	}
}

func TestGenerateProjectsToColsUsed(t *testing.T) {
	gen := Generate(staticScan(npmRecord("left-pad", "1.0.0", "/a/package.json")))
	ctx := WithColsUsed(context.Background(), []string{"package_name", "version"})
	rows, err := gen(ctx, osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	wantKeys(t, rows[0], "package_name", "version")
	if rows[0]["package_name"] != "left-pad" || rows[0]["version"] != "1.0.0" {
		t.Errorf("row = %v, want the record's values", rows[0])
	}
}

func TestGenerateWithoutColsUsedReturnsEveryColumn(t *testing.T) {
	gen := Generate(staticScan(npmRecord("left-pad", "1.0.0", "/a/package.json")))
	rows, err := gen(context.Background(), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if len(rows[0]) != len(Columns()) {
		t.Errorf("row has %d cells, want %d (one per column)", len(rows[0]), len(Columns()))
	}
}

func TestGenerateDistinctProjectsToColsUsed(t *testing.T) {
	gen := GenerateDistinct(staticScan(
		npmRecord("left-pad", "1.0.0", "/a/package.json"),
		npmRecord("left-pad", "1.0.0", "/b/package.json"),
	))
	ctx := WithColsUsed(context.Background(), []string{"package_name", "install_count"})
	rows, err := gen(ctx, osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	wantKeys(t, rows[0], "install_count", "package_name")
	if rows[0]["install_count"] != "2" {
		t.Errorf("install_count = %q, want 2", rows[0]["install_count"])
	}
}

// D8a: grouping uses the unprojected row. Two records differing only in a
// column the query never selected must stay two rows — otherwise
// install_count would silently depend on the SELECT list.
func TestGenerateDistinctGroupsOnUnprojectedRow(t *testing.T) {
	gen := GenerateDistinct(staticScan(
		npmRecord("left-pad", "1.0.0", "/a/package.json"),
		npmRecord("left-pad", "2.0.0", "/b/package.json"),
	))
	ctx := WithColsUsed(context.Background(), []string{"package_name", "install_count"})
	rows, err := gen(ctx, osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (versions differ, so the groups must not merge)", len(rows))
	}
	for _, r := range rows {
		if r["install_count"] != "1" {
			t.Errorf("install_count = %q, want 1", r["install_count"])
		}
	}
}

// A bare count(*) sends an empty colsUsed. Rows must still be counted.
func TestGenerateEmptyColsUsedReturnsCellLessRows(t *testing.T) {
	gen := Generate(staticScan(
		npmRecord("left-pad", "1.0.0", "/a/package.json"),
		npmRecord("right-pad", "1.0.0", "/b/package.json"),
	))
	rows, err := gen(WithColsUsed(context.Background(), nil), osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if len(r) != 0 {
			t.Errorf("row = %v, want no cells", r)
		}
	}
}

func TestGenerateAgentConfigProjectsToColsUsed(t *testing.T) {
	gen := GenerateAgentConfig(staticScan(agentConfigRecord()))
	ctx := WithColsUsed(context.Background(), []string{"name", "has_network_access"})
	rows, err := gen(ctx, osqtable.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	wantKeys(t, rows[0], "has_network_access", "name")
	if rows[0]["has_network_access"] != "1" {
		t.Errorf("has_network_access = %q, want 1", rows[0]["has_network_access"])
	}
}

// A column used only in WHERE is included in colsUsed by osquery, hidden
// columns included. Projecting to that set therefore cannot break
// SQLite's re-verification of the predicate against the returned rows.
func TestGenerateKeepsConstrainedHiddenColumn(t *testing.T) {
	rec := npmRecord("left-pad", "1.0.0", "/a/package.json")
	rec.Profile = "deep"
	gen := Generate(staticScan(rec))
	ctx := WithColsUsed(context.Background(), []string{"package_name", "profile"})
	rows, err := gen(ctx, qc(map[string][]osqtable.Constraint{"profile": {eq("deep")}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0]["profile"] != "deep" {
		t.Errorf("profile = %q, want deep (the predicate would drop the row)", rows[0]["profile"])
	}
}

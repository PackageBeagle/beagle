package table

import (
	"context"
	"errors"
	"strings"
	"testing"

	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
	"github.com/packagebeagle/beagle/internal/scanner"
)

func eq(expr string) osqtable.Constraint {
	return osqtable.Constraint{Operator: osqtable.OperatorEquals, Expression: expr}
}

func qc(constraints map[string][]osqtable.Constraint) osqtable.QueryContext {
	out := osqtable.QueryContext{Constraints: map[string]osqtable.ConstraintList{}}
	for col, cs := range constraints {
		out.Constraints[col] = osqtable.ConstraintList{Constraints: cs}
	}
	return out
}

// fakeScan records the arguments Generate translated from the query
// context and returns a canned outcome.
type fakeScan struct {
	profile  string
	explicit []string
	outcome  ScanOutcome
	err      error
	calls    int
}

func (f *fakeScan) fn(_ context.Context, profile string, explicit []string) (ScanOutcome, error) {
	f.calls++
	f.profile = profile
	f.explicit = explicit
	return f.outcome, f.err
}

func TestGenerateDefaultsProfileToBaseline(t *testing.T) {
	f := &fakeScan{}
	if _, err := Generate(f.fn)(context.Background(), qc(nil)); err != nil {
		t.Fatal(err)
	}
	if f.profile != model.ProfileBaseline {
		t.Fatalf("profile = %q, want %q", f.profile, model.ProfileBaseline)
	}
	if len(f.explicit) != 0 {
		t.Fatalf("explicit roots = %v, want none", f.explicit)
	}
}

func TestGenerateProfileEquality(t *testing.T) {
	f := &fakeScan{}
	ctx := qc(map[string][]osqtable.Constraint{"profile": {eq("deep")}, "root": {eq("/tmp/x")}})
	if _, err := Generate(f.fn)(context.Background(), ctx); err != nil {
		t.Fatal(err)
	}
	if f.profile != "deep" {
		t.Fatalf("profile = %q, want deep", f.profile)
	}
	if len(f.explicit) != 1 || f.explicit[0] != "/tmp/x" {
		t.Fatalf("explicit = %v, want [/tmp/x]", f.explicit)
	}
}

func TestGenerateProfileNonEqualsErrors(t *testing.T) {
	f := &fakeScan{}
	ctx := qc(map[string][]osqtable.Constraint{
		"profile": {{Operator: osqtable.OperatorLike, Expression: "deep"}},
	})
	_, err := Generate(f.fn)(context.Background(), ctx)
	if err == nil || !strings.Contains(err.Error(), "profile only supports '='") {
		t.Fatalf("err = %v, want profile operator error", err)
	}
	if f.calls != 0 {
		t.Fatal("scan ran despite constraint error")
	}
}

func TestGenerateConflictingProfilesError(t *testing.T) {
	f := &fakeScan{}
	ctx := qc(map[string][]osqtable.Constraint{"profile": {eq("baseline"), eq("deep")}})
	_, err := Generate(f.fn)(context.Background(), ctx)
	if err == nil || !strings.Contains(err.Error(), "conflicting profile values") {
		t.Fatalf("err = %v, want conflicting-profile error", err)
	}
}

func TestGenerateNonEqualsRootIgnoredForScoping(t *testing.T) {
	f := &fakeScan{}
	ctx := qc(map[string][]osqtable.Constraint{
		"root": {{Operator: osqtable.OperatorLike, Expression: "/Users/%"}},
	})
	if _, err := Generate(f.fn)(context.Background(), ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.explicit) != 0 {
		t.Fatalf("explicit = %v; LIKE must not become a scan root", f.explicit)
	}
}

func TestGenerateMultipleRootEqualities(t *testing.T) {
	f := &fakeScan{}
	ctx := qc(map[string][]osqtable.Constraint{"root": {eq("/a"), eq("/b")}})
	if _, err := Generate(f.fn)(context.Background(), ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.explicit) != 2 {
		t.Fatalf("explicit = %v, want both roots", f.explicit)
	}
}

func TestGenerateScanErrorPropagates(t *testing.T) {
	f := &fakeScan{err: errors.New("profile=deep requires at least one explicit root")}
	_, err := Generate(f.fn)(context.Background(), qc(nil))
	if err == nil || !strings.Contains(err.Error(), "requires at least one explicit root") {
		t.Fatalf("err = %v, want scan error surfaced", err)
	}
}

// TestGenerateRootColumnVerbatim pins the trailing-slash contract:
// SQLite re-verifies WHERE predicates on returned rows, so the root
// column must be byte-for-byte what was constrained, never cleaned.
func TestGenerateRootColumnVerbatim(t *testing.T) {
	const dirty = "/tmp/spikex/"
	f := &fakeScan{outcome: ScanOutcome{
		Records: []model.Record{{
			RecordType: model.RecordTypePackage,
			SourceFile: "/tmp/spikex/package.json",
		}},
		Roots: []scanner.Root{{Path: dirty, Kind: model.RootKindUnknown}},
	}}
	rows, err := Generate(f.fn)(context.Background(), qc(map[string][]osqtable.Constraint{"root": {eq(dirty)}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if got := rows[0]["root"]; got != dirty {
		t.Fatalf("root = %q, want verbatim %q", got, dirty)
	}
}

func TestNewRootPathLookupLongestWins(t *testing.T) {
	lookup := newRootPathLookup([]scanner.Root{
		{Path: "/a"},
		{Path: "/a/b/"},
	})
	if got := lookup("/a/b/c/file"); got != "/a/b/" {
		t.Fatalf("lookup = %q, want longest enclosing root verbatim", got)
	}
	if got := lookup("/elsewhere/file"); got != "" {
		t.Fatalf("lookup outside roots = %q, want empty", got)
	}
	if got := lookup(""); got != "" {
		t.Fatalf("lookup(\"\") = %q, want empty", got)
	}
}

func TestRecordRowTriStateAndSpecials(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		name string
		dd   *bool
		want string
	}{
		{"nil is empty (NULL)", nil, ""},
		{"true is 1", &tr, "1"},
		{"false is 0", &fa, "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := recordRow(model.Record{DirectDependency: c.dd}, "", false)
			if row["direct_dependency"] != c.want {
				t.Fatalf("direct_dependency = %q, want %q", row["direct_dependency"], c.want)
			}
		})
	}

	row := recordRow(model.Record{
		HasLifecycleScripts: true,
		LifecycleScripts:    []string{"postinstall", "preinstall"},
	}, "/r", true)
	if row["has_lifecycle_scripts"] != "1" {
		t.Fatalf("has_lifecycle_scripts = %q", row["has_lifecycle_scripts"])
	}
	if row["lifecycle_scripts"] != `["postinstall","preinstall"]` {
		t.Fatalf("lifecycle_scripts = %q, want JSON array", row["lifecycle_scripts"])
	}
	if row["scan_truncated"] != "1" {
		t.Fatalf("scan_truncated = %q, want 1", row["scan_truncated"])
	}
	if row["root"] != "/r" {
		t.Fatalf("root = %q", row["root"])
	}

	empty := recordRow(model.Record{}, "", false)
	if empty["lifecycle_scripts"] != "" {
		t.Fatalf("empty lifecycle_scripts = %q, want empty", empty["lifecycle_scripts"])
	}
	if empty["scan_truncated"] != "0" {
		t.Fatalf("scan_truncated = %q, want 0", empty["scan_truncated"])
	}
}

// TestRecordRowMatchesColumns keeps the row map and the declared schema
// in lockstep: a column without a cell (or a cell without a column)
// is a silent data hole in osquery.
func TestRecordRowMatchesColumns(t *testing.T) {
	row := recordRow(model.Record{}, "", false)
	cols := Columns()
	if len(row) != len(cols) {
		t.Fatalf("row has %d cells, schema has %d columns", len(row), len(cols))
	}
	for _, c := range cols {
		if _, ok := row[c.Name]; !ok {
			t.Fatalf("column %q missing from row map", c.Name)
		}
	}
}

func TestRecordRowOmitsConstantColumns(t *testing.T) {
	row := recordRow(model.Record{
		Endpoint: model.Endpoint{Username: "alice", Hostname: "h", UID: "501"},
	}, "", false)
	removed := []string{
		"record_type", "record_id", "schema_version", "scanner_name",
		"scanner_version", "run_id", "scan_time", "endpoint_hostname",
		"endpoint_os", "endpoint_arch", "endpoint_uid", "endpoint_device_id",
		"project_path",
	}
	for _, c := range removed {
		if _, ok := row[c]; ok {
			t.Errorf("column %q should have been removed from the row map", c)
		}
	}
	if row["endpoint_username"] != "alice" {
		t.Errorf("endpoint_username = %q, want alice (retained)", row["endpoint_username"])
	}
}

func TestScopeColumnsHiddenAndIndexed(t *testing.T) {
	want := map[string]bool{"profile": true, "root": true}
	seen := map[string]bool{}
	for _, c := range Columns() {
		if !want[c.Name] {
			continue
		}
		seen[c.Name] = true
		if !c.Hidden {
			t.Errorf("column %q: Hidden = false, want true", c.Name)
		}
		if !c.Index {
			t.Errorf("column %q: Index = false, want true", c.Name)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("column %q missing from schema", name)
		}
	}
}

func pkgRow(eco string) model.Record {
	return model.Record{RecordType: model.RecordTypePackage, Ecosystem: eco}
}

func TestGenerateEcosystemFilterSingle(t *testing.T) {
	f := &fakeScan{outcome: ScanOutcome{Records: []model.Record{
		pkgRow("npm"), pkgRow("pypi"),
	}}}
	rows, err := Generate(f.fn)(context.Background(), qc(map[string][]osqtable.Constraint{
		"ecosystem": {eq("pypi")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["ecosystem"] != "pypi" {
		t.Fatalf("rows = %v, want single pypi row", rows)
	}
}

func TestGenerateEcosystemFilterMultiValue(t *testing.T) {
	f := &fakeScan{outcome: ScanOutcome{Records: []model.Record{
		pkgRow("npm"), pkgRow("pypi"), pkgRow("go"),
	}}}
	rows, err := Generate(f.fn)(context.Background(), qc(map[string][]osqtable.Constraint{
		"ecosystem": {eq("npm"), eq("go")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (npm+go union)", len(rows))
	}
}

func TestGenerateEcosystemNonEqualsIgnored(t *testing.T) {
	f := &fakeScan{outcome: ScanOutcome{Records: []model.Record{
		pkgRow("npm"), pkgRow("pypi"),
	}}}
	rows, err := Generate(f.fn)(context.Background(), qc(map[string][]osqtable.Constraint{
		"ecosystem": {{Operator: osqtable.OperatorLike, Expression: "np%"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (LIKE is not pushed down)", len(rows))
	}
}

func TestGenerateNoEcosystemConstraintKeepsAll(t *testing.T) {
	f := &fakeScan{outcome: ScanOutcome{Records: []model.Record{
		pkgRow("npm"), pkgRow("pypi"),
	}}}
	rows, err := Generate(f.fn)(context.Background(), qc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (no filter)", len(rows))
	}
}

func TestFilterByEcosystemDoesNotMutateInput(t *testing.T) {
	recs := []model.Record{pkgRow("npm"), pkgRow("pypi"), pkgRow("go")}
	got := filterByEcosystem(recs, qc(map[string][]osqtable.Constraint{
		"ecosystem": {eq("pypi")},
	}))
	if len(got) != 1 || got[0].Ecosystem != "pypi" {
		t.Fatalf("filtered = %v, want [pypi]", got)
	}
	want := []string{"npm", "pypi", "go"}
	for i, w := range want {
		if recs[i].Ecosystem != w {
			t.Fatalf("input slice mutated at %d: got %q, want %q (cache corruption hazard)", i, recs[i].Ecosystem, w)
		}
	}
}

func TestDistinctColumnsDropsSourceFileAddsAggregates(t *testing.T) {
	names := map[string]bool{}
	for _, c := range DistinctColumns() {
		names[c.Name] = true
	}
	if names["source_file"] {
		t.Error("source_file must be dropped from the distinct schema")
	}
	for _, want := range []string{"install_count", "source_files"} {
		if !names[want] {
			t.Errorf("distinct schema missing %q", want)
		}
	}
	// One fewer than Columns() (source_file removed) plus two aggregates.
	if got, want := len(DistinctColumns()), len(Columns())-1+2; got != want {
		t.Fatalf("distinct schema has %d columns, want %d", got, want)
	}
}

func TestDistinctColumnsKeepScopeHiddenIndex(t *testing.T) {
	want := map[string]bool{"profile": true, "root": true}
	seen := map[string]bool{}
	for _, c := range DistinctColumns() {
		if !want[c.Name] {
			continue
		}
		seen[c.Name] = true
		if !c.Hidden || !c.Index {
			t.Errorf("column %q: Hidden=%v Index=%v, want both true", c.Name, c.Hidden, c.Index)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("distinct schema missing scope column %q", name)
		}
	}
}

func TestDedupeCollapsesBySourceFile(t *testing.T) {
	tr := true
	mk := func(sf string) model.Record {
		return model.Record{
			RecordType: model.RecordTypePackage, Ecosystem: "npm",
			PackageName: "left-pad", Version: "1.3.0",
			DirectDependency: &tr, SourceFile: sf,
		}
	}
	rows := dedupeRows([]model.Record{mk("/a/package.json"), mk("/b/package.json")},
		func(string) string { return "" }, false)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (collapsed)", len(rows))
	}
	if rows[0]["install_count"] != "2" {
		t.Fatalf("install_count = %q, want 2", rows[0]["install_count"])
	}
	if rows[0]["source_files"] != `["/a/package.json","/b/package.json"]` {
		t.Fatalf("source_files = %q", rows[0]["source_files"])
	}
	if _, ok := rows[0]["source_file"]; ok {
		t.Fatal("distinct row must not carry a scalar source_file cell")
	}
}

func TestDedupeKeepsDistinctRecordsSeparate(t *testing.T) {
	mk := func(name, sf string) model.Record {
		return model.Record{RecordType: model.RecordTypePackage, Ecosystem: "npm", PackageName: name, SourceFile: sf}
	}
	rows := dedupeRows([]model.Record{mk("a", "/x"), mk("b", "/y")},
		func(string) string { return "" }, false)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (different package_name stays separate)", len(rows))
	}
}

func TestDistinctKeyInjectiveWithEmbeddedDelimiters(t *testing.T) {
	// Two rows differ only in how a payload splits across adjacent sorted
	// columns. A naive name+NUL+value+NUL join collides here (both become
	// "a\x001\x00b\x002\x00b\x003\x00"); the length-prefixed key must not.
	r1 := map[string]string{"a": "1\x00b\x002", "b": "3"}
	r2 := map[string]string{"a": "1", "b": "2\x00b\x003"}
	if distinctKey(r1) == distinctKey(r2) {
		t.Fatal("distinctKey collided on distinct rows with embedded delimiter bytes")
	}
}

func TestDedupeSourceFilesSortedUniqueDeterministic(t *testing.T) {
	mk := func(sf string) model.Record {
		return model.Record{RecordType: model.RecordTypePackage, Ecosystem: "npm", PackageName: "p", SourceFile: sf}
	}
	// Unsorted input with a duplicate path.
	rows := dedupeRows([]model.Record{mk("/z"), mk("/a"), mk("/m"), mk("/a")},
		func(string) string { return "" }, false)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0]["source_files"] != `["/a","/m","/z"]` {
		t.Fatalf("source_files = %q, want sorted+unique", rows[0]["source_files"])
	}
	if rows[0]["install_count"] != "3" {
		t.Fatalf("install_count = %q, want 3 (distinct paths)", rows[0]["install_count"])
	}
}

func TestDedupeRowMatchesDistinctColumns(t *testing.T) {
	rows := dedupeRows([]model.Record{{RecordType: model.RecordTypePackage}},
		func(string) string { return "" }, false)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	cols := DistinctColumns()
	if len(rows[0]) != len(cols) {
		t.Fatalf("row has %d cells, distinct schema has %d columns", len(rows[0]), len(cols))
	}
	for _, c := range cols {
		if _, ok := rows[0][c.Name]; !ok {
			t.Fatalf("column %q missing from distinct row", c.Name)
		}
	}
}

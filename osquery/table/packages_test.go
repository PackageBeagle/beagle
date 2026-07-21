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

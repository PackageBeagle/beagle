package table

import (
	"context"
	"testing"

	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
)

// osquery declares every hidden+index column as the SQLite PRIMARY KEY,
// and SQLite drops DISTINCT when a query pins every key column with '='.
// row_key makes that key unique, so each table must declare it
// hidden+index.
func TestRowKeyColumnHiddenIndexedOnEveryTable(t *testing.T) {
	schemas := map[string][]osqtable.ColumnDefinition{
		"beagle_packages":          Columns(),
		"beagle_distinct_packages": DistinctColumns(),
		"beagle_agent_config":      AgentConfigColumns(),
	}
	for table, cols := range schemas {
		found := false
		for _, c := range cols {
			if c.Name != rowKeyColumn {
				continue
			}
			found = true
			if !c.Hidden || !c.Index {
				t.Errorf("%s.%s: Hidden=%v Index=%v, want both true", table, c.Name, c.Hidden, c.Index)
			}
		}
		if !found {
			t.Errorf("%s has no %s column", table, rowKeyColumn)
		}
	}
}

// Rows that share profile, root and exclude, which every row of one scan
// does, must still differ in row_key, or the declared key is a lie.
func TestRowKeyUniqueWithinEveryTable(t *testing.T) {
	pkgs := []model.Record{
		npmRecord("a", "1.0.0", "/p/a/package.json"),
		npmRecord("b", "1.0.0", "/p/b/package.json"),
		npmRecord("c", "2.0.0", "/p/c/package.json"),
	}
	cfg1, cfg2 := agentConfigRecord(), agentConfigRecord()
	cfg2.PackageName = "PreToolUse:*"
	cfg2.SourceFile = "/home/u/.claude/other.json"

	ctx := qc(map[string][]osqtable.Constraint{"profile": {eq("deep")}, "root": {eq("/p")}})
	cases := map[string]struct {
		gen  osqtable.GenerateFunc
		want int
	}{
		"beagle_packages":          {Generate(staticScan(pkgs...)), 3},
		"beagle_distinct_packages": {GenerateDistinct(staticScan(pkgs...)), 3},
		"beagle_agent_config":      {GenerateAgentConfig(staticScan(cfg1, cfg2)), 2},
	}
	for table, c := range cases {
		rows, err := c.gen(context.Background(), ctx)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if len(rows) != c.want {
			t.Fatalf("%s: got %d rows, want %d", table, len(rows), c.want)
		}
		seen := map[string]bool{}
		for _, r := range rows {
			k, ok := r[rowKeyColumn]
			if !ok || k == "" {
				t.Fatalf("%s: row without %s: %v", table, rowKeyColumn, r)
			}
			if seen[k] {
				t.Fatalf("%s: duplicate %s %q", table, rowKeyColumn, k)
			}
			seen[k] = true
		}
	}
}

// Distinct rows group on every column except source_file; row_key must
// not take part, or no two records would ever collapse.
func TestRowKeyDoesNotSplitDistinctGroups(t *testing.T) {
	gen := GenerateDistinct(staticScan(
		npmRecord("left-pad", "1.0.0", "/a/package.json"),
		npmRecord("left-pad", "1.0.0", "/b/package.json"),
	))
	rows, err := gen(context.Background(), qc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["install_count"] != "2" {
		t.Fatalf("rows = %v, want one row with install_count 2", rows)
	}
}

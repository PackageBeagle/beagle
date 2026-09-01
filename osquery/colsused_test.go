package main

import (
	"context"
	"sort"
	"strings"
	"testing"

	genosquery "github.com/osquery/osquery-go/gen/osquery"
	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
	beagletable "github.com/packagebeagle/beagle/osquery/table"
)

func TestParseColsUsedReadsTheField(t *testing.T) {
	// Captured from osqueryd 5.23.1 for
	// SELECT col_a, col_c FROM probe_cols WHERE col_b = 'b'.
	raw := `{"constraints":[{"name":"col_b","list":[{"op":2,"expr":"b"}],"affinity":"TEXT"}],` +
		`"colsUsed":["col_a","col_b","col_c"],"colsUsedBitset":7}`
	cols, ok := parseColsUsed(raw)
	if !ok {
		t.Fatal("parseColsUsed reported no colsUsed, want the field")
	}
	sort.Strings(cols)
	if strings.Join(cols, ",") != "col_a,col_b,col_c" {
		t.Errorf("cols = %v, want [col_a col_b col_c]", cols)
	}
}

// An osquery build that does not send colsUsed must be reported as
// absent, which is what makes the table fall back to every column.
func TestParseColsUsedAbsentField(t *testing.T) {
	if cols, ok := parseColsUsed(`{"constraints":[]}`); ok {
		t.Errorf("cols = %v, ok = true; want absent", cols)
	}
}

// A bare count(*) sends an empty list. That is a real answer meaning
// "reads no columns", not a missing field.
func TestParseColsUsedEmptyListIsPresent(t *testing.T) {
	cols, ok := parseColsUsed(`{"constraints":[],"colsUsed":[],"colsUsedBitset":0}`)
	if !ok {
		t.Fatal("empty colsUsed reported as absent, want present")
	}
	if len(cols) != 0 {
		t.Errorf("cols = %v, want empty", cols)
	}
}

// Malformed context JSON is osquery-go's error to report from its own
// parse; the wrapper must not panic or invent a projection.
func TestParseColsUsedMalformedJSON(t *testing.T) {
	if cols, ok := parseColsUsed(`{"colsUsed":`); ok {
		t.Errorf("cols = %v, ok = true; want absent for malformed JSON", cols)
	}
}

func staticScanFunc(records ...model.Record) beagletable.ScanFunc {
	return func(context.Context, string, []string) (beagletable.ScanOutcome, error) {
		return beagletable.ScanOutcome{Records: records}, nil
	}
}

func packagesPlugin() *osqtable.Plugin {
	scan := staticScanFunc(model.Record{
		Ecosystem:      model.EcosystemNPM,
		PackageName:    "left-pad",
		NormalizedName: "left-pad",
		Version:        "1.0.0",
		SourceFile:     "/a/package.json",
	})
	return osqtable.NewPlugin("beagle_packages", beagletable.Columns(), beagletable.Generate(scan))
}

func generate(t *testing.T, plugin interface {
	Call(context.Context, genosquery.ExtensionPluginRequest) genosquery.ExtensionResponse
}, queryContext string) genosquery.ExtensionPluginResponse {
	t.Helper()
	resp := plugin.Call(context.Background(), genosquery.ExtensionPluginRequest{
		"action":  "generate",
		"context": queryContext,
	})
	if resp.Status == nil || resp.Status.Code != 0 {
		t.Fatalf("status = %+v, want code 0", resp.Status)
	}
	return resp.Response
}

func TestWrappedPluginProjectsGeneratedRows(t *testing.T) {
	rows := generate(t, withColsUsed(packagesPlugin()),
		`{"constraints":[],"colsUsed":["package_name","version"],"colsUsedBitset":3}`)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if len(rows[0]) != 2 || rows[0]["package_name"] != "left-pad" || rows[0]["version"] != "1.0.0" {
		t.Errorf("row = %v, want only package_name and version", rows[0])
	}
}

func TestWrappedPluginWithoutColsUsedReturnsEveryColumn(t *testing.T) {
	rows := generate(t, withColsUsed(packagesPlugin()), `{"constraints":[]}`)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if len(rows[0]) != len(beagletable.Columns()) {
		t.Errorf("row has %d cells, want %d (one per column)", len(rows[0]), len(beagletable.Columns()))
	}
}

// The wrapper must stay transparent for everything else osquery asks of
// a table plugin; the columns action is how osquery learns the schema.
func TestWrappedPluginDelegatesColumnsAction(t *testing.T) {
	plugin := withColsUsed(packagesPlugin())
	resp := plugin.Call(context.Background(), genosquery.ExtensionPluginRequest{"action": "columns"})
	if resp.Status == nil || resp.Status.Code != 0 {
		t.Fatalf("status = %+v, want code 0", resp.Status)
	}
	if len(resp.Response) != len(beagletable.Columns()) {
		t.Errorf("got %d column routes, want %d", len(resp.Response), len(beagletable.Columns()))
	}
}

func TestWrappedPluginKeepsNameAndRegistry(t *testing.T) {
	plugin := withColsUsed(packagesPlugin())
	if plugin.Name() != "beagle_packages" {
		t.Errorf("Name = %q, want beagle_packages", plugin.Name())
	}
	if plugin.RegistryName() != "table" {
		t.Errorf("RegistryName = %q, want table", plugin.RegistryName())
	}
}

// Malformed context JSON stays osquery-go's error to report: the wrapper
// passes it through rather than masking it with a projection failure.
func TestWrappedPluginPassesThroughParseErrors(t *testing.T) {
	plugin := withColsUsed(packagesPlugin())
	resp := plugin.Call(context.Background(), genosquery.ExtensionPluginRequest{
		"action":  "generate",
		"context": `{"constraints":`,
	})
	if resp.Status == nil || resp.Status.Code == 0 {
		t.Fatalf("status = %+v, want a non-zero code", resp.Status)
	}
	if !strings.Contains(resp.Status.Message, "context JSON") {
		t.Errorf("message = %q, want osquery-go's context parse error", resp.Status.Message)
	}
}

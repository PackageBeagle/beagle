package main

import (
	"context"
	"encoding/json"

	"github.com/osquery/osquery-go"
	genosquery "github.com/osquery/osquery-go/gen/osquery"

	beagletable "github.com/packagebeagle/beagle/osquery/table"
)

// colsUsedPlugin recovers the colsUsed field osquery sends and
// osquery-go drops, attaching it to the context the table's GenerateFunc
// receives. Everything else delegates to the embedded plugin.
//
// osqueryd puts the columns a query reads in the generate request's
// context JSON, alongside the constraints:
//
//	{"constraints":[...],"colsUsed":["col_a","col_b"],"colsUsedBitset":3}
//
// osquery-go's queryContextJSON declares a field for constraints and
// nothing else, so json.Unmarshal discards the rest and QueryContext has
// no way to expose it. Wrapping the plugin rather than forking the
// library: the field is additive information the library does not model,
// and its table plugin is otherwise exactly what we want.
type colsUsedPlugin struct {
	osquery.OsqueryPlugin
}

// withColsUsed wraps a table plugin so its GenerateFunc can project rows
// to the columns the query actually reads.
func withColsUsed(plugin osquery.OsqueryPlugin) osquery.OsqueryPlugin {
	return colsUsedPlugin{OsqueryPlugin: plugin}
}

func (p colsUsedPlugin) Call(
	ctx context.Context, request genosquery.ExtensionPluginRequest,
) genosquery.ExtensionResponse {
	if request["action"] == "generate" {
		if cols, ok := parseColsUsed(request["context"]); ok {
			ctx = beagletable.WithColsUsed(ctx, cols)
		}
	}
	return p.OsqueryPlugin.Call(ctx, request)
}

// parseColsUsed returns the columns named by the request's colsUsed
// field and whether the field was there at all. Absent means the table
// returns every column, so an osquery build that does not send colsUsed
// — or a context this code fails to parse — degrades to the previous
// behavior rather than to empty rows. Malformed JSON is left for
// osquery-go to report from its own parse of the same string.
func parseColsUsed(queryContextJSON string) ([]string, bool) {
	var parsed struct {
		ColsUsed *[]string `json:"colsUsed"`
	}
	if err := json.Unmarshal([]byte(queryContextJSON), &parsed); err != nil {
		return nil, false
	}
	if parsed.ColsUsed == nil {
		return nil, false
	}
	return *parsed.ColsUsed, true
}

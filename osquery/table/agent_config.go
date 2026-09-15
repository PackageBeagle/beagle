package table

import (
	"context"

	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
)

// Extras keys read off agent-config records. Duplicated from
// internal/ecosystem/agentcfg rather than imported: this package maps
// records to rows and should not depend on a scanner package.
const (
	extraHasDynamicContext    = "has_dynamic_context"
	extraHasUnrestrictedTools = "has_unrestricted_tools"
	extraHasNetworkAccess     = "has_network_access"
	extraHasCredentialAccess  = "has_credential_access"
	extraRiskSignals          = "risk_signals"
)

// AgentConfigColumns returns the beagle_agent_config schema.
//
// The four has_* columns are raw signals, not verdicts.
// has_unrestricted_tools reports that a skill can reach tools nothing
// narrows: it declares no allowed-tools and so inherits the
// conversation's, or declares a grant with no scope or a scope of "*".
// Most skills declare no allowed-tools, so a 1 here is the true
// denominator rather than a filter on its own; it becomes one in
// conjunction with scope and digest rarity. risk_signals.tool_scope
// records which of the three cases applies.
func AgentConfigColumns() []osqtable.ColumnDefinition {
	return []osqtable.ColumnDefinition{
		osqtable.TextColumn("endpoint_username"),
		osqtable.TextColumn("config_type"),
		osqtable.TextColumn("scope"),
		osqtable.TextColumn("agent"),
		osqtable.TextColumn("name"),
		osqtable.TextColumn("source_file"),
		osqtable.TextColumn("project_path"),
		// File identity. The digest is excluded from record_id on purpose
		// (see model.Record.StableID), so a mutated file keeps its row and
		// moves this column — which is what a detection rule diffs.
		osqtable.TextColumn("file_sha256"),
		osqtable.TextColumn("file_modified"),
		osqtable.IntegerColumn("has_dynamic_context"),
		osqtable.IntegerColumn("has_unrestricted_tools"),
		osqtable.IntegerColumn("has_network_access"),
		osqtable.IntegerColumn("has_credential_access"),
		osqtable.TextColumn("risk_signals"),
		// Scope: hidden+index constraint inputs, same semantics as
		// beagle_packages.
		osqtable.TextColumn("profile", osqtable.HiddenColumn(), osqtable.IndexColumn()),
		osqtable.TextColumn("root", osqtable.HiddenColumn(), osqtable.IndexColumn()),
		osqtable.IntegerColumn("scan_truncated"),
	}
}

// GenerateAgentConfig maps the constrained scan's agent-config records to
// beagle_agent_config rows. Both tables share one scan and one cache, so
// querying either warms the other.
func GenerateAgentConfig(scan ScanFunc) osqtable.GenerateFunc {
	return func(ctx context.Context, qc osqtable.QueryContext) ([]map[string]string, error) {
		records, rootFor, truncated, err := scanForQuery(ctx, scan, qc, "beagle_agent_config")
		if err != nil {
			return nil, err
		}
		cols := colsUsedFrom(ctx)
		rows := make([]map[string]string, 0, len(records))
		for _, r := range records {
			if r.Ecosystem != model.EcosystemAgentConfig {
				continue
			}
			row := agentConfigRow(r, rootFor(r.SourceFile), truncated)
			projectRow(row, cols)
			rows = append(rows, row)
		}
		return rows, nil
	}
}

// agentConfigRow maps one agent-config record to an osquery row. Extras
// may be absent on a malformed record; a missing boolean reads as 0
// rather than an empty INTEGER cell, which osquery would coerce to NULL.
func agentConfigRow(r model.Record, rootPath string, truncated bool) map[string]string {
	return map[string]string{
		"endpoint_username":      r.Endpoint.Username,
		"config_type":            r.SourceType,
		"scope":                  r.InstallScope,
		"agent":                  r.PackageManager,
		"name":                   r.PackageName,
		"source_file":            r.SourceFile,
		"project_path":           r.ProjectPath,
		"file_sha256":            r.SourceFileSHA256,
		"file_modified":          r.SourceFileModified,
		"has_dynamic_context":    extraBool(r.Extras, extraHasDynamicContext),
		"has_unrestricted_tools": extraBool(r.Extras, extraHasUnrestrictedTools),
		"has_network_access":     extraBool(r.Extras, extraHasNetworkAccess),
		"has_credential_access":  extraBool(r.Extras, extraHasCredentialAccess),
		"risk_signals":           r.Extras[extraRiskSignals],
		"profile":                r.Profile,
		"root":                   rootPath,
		"scan_truncated":         boolCell(truncated),
	}
}

func extraBool(extras map[string]string, key string) string {
	if extras[key] == "1" {
		return "1"
	}
	return "0"
}

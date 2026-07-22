// Package table implements the beagle_packages osquery table: column
// definitions, query-constraint translation, and record-to-row mapping.
//
// The scan itself is injected as a ScanFunc so this package stays free
// of caching and process-configuration concerns (those live in the
// extension entrypoint).
package table

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	osqtable "github.com/osquery/osquery-go/plugin/table"

	"github.com/packagebeagle/beagle/internal/model"
	"github.com/packagebeagle/beagle/internal/scanner"
)

// ScanOutcome is what one scan (or cache hit) hands back for row mapping.
type ScanOutcome struct {
	Records []model.Record
	// Roots are the resolved scan roots with their paths exactly as
	// configured/constrained. Row mapping needs them to compute the
	// enclosing-root output column.
	Roots []scanner.Root
	// Truncated reports that the scan did not run to completion; every
	// row from it carries scan_truncated=1.
	Truncated bool
}

// ScanFunc runs (or serves from cache) one scan for the given profile
// and explicit roots. explicitRoots empty means the profile's curated
// defaults.
type ScanFunc func(ctx context.Context, profile string, explicitRoots []string) (ScanOutcome, error)

// Columns returns the beagle_packages schema.
func Columns() []osqtable.ColumnDefinition {
	return []osqtable.ColumnDefinition{
		// Endpoint (username varies per record under BEAGLE_ALL_USERS).
		osqtable.TextColumn("endpoint_username"),
		// Package fields.
		osqtable.TextColumn("ecosystem"),
		osqtable.TextColumn("package_name"),
		osqtable.TextColumn("normalized_name"),
		osqtable.TextColumn("version"),
		osqtable.TextColumn("root_kind"),
		osqtable.TextColumn("install_scope"),
		osqtable.TextColumn("package_manager"),
		osqtable.TextColumn("source_type"),
		osqtable.TextColumn("source_file"),
		osqtable.TextColumn("confidence"),
		osqtable.TextColumn("requested_spec"),
		osqtable.TextColumn("server_name"),
		osqtable.IntegerColumn("direct_dependency"),
		osqtable.IntegerColumn("has_lifecycle_scripts"),
		osqtable.TextColumn("lifecycle_scripts"),
		// Scope: hidden+index constraint inputs — usable in WHERE, omitted
		// from SELECT *. Their cells stay in the row map because SQLite
		// re-verifies WHERE predicates against returned rows.
		osqtable.TextColumn("profile", osqtable.HiddenColumn(), osqtable.IndexColumn()),
		osqtable.TextColumn("root", osqtable.HiddenColumn(), osqtable.IndexColumn()),
		// Status.
		osqtable.IntegerColumn("scan_truncated"),
	}
}

// ecosystemFilterSet returns the ecosystems constrained by EQUALS in qc,
// or nil when there is no such constraint. nil means "no filter".
// Non-EQUALS operators (LIKE, !=, …) are ignored here; SQLite
// post-filters them against the returned rows, mirroring root handling.
func ecosystemFilterSet(qc osqtable.QueryContext) map[string]struct{} {
	cl, ok := qc.Constraints["ecosystem"]
	if !ok {
		return nil
	}
	set := make(map[string]struct{})
	for _, c := range cl.Constraints {
		if c.Operator == osqtable.OperatorEquals {
			set[c.Expression] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// filterByEcosystem returns the records whose Ecosystem is in the EQUALS
// constraint set. With no ecosystem constraint it returns records
// unchanged. It never mutates records: the input is the cached scan
// outcome, shared across queries and tables.
func filterByEcosystem(records []model.Record, qc osqtable.QueryContext) []model.Record {
	set := ecosystemFilterSet(qc)
	if set == nil {
		return records
	}
	out := make([]model.Record, 0, len(records))
	for _, r := range records {
		if _, ok := set[r.Ecosystem]; ok {
			out = append(out, r)
		}
	}
	return out
}

// Generate translates query constraints into a scan and maps the
// resulting records to rows.
//
// Constraint semantics (verified against osqueryd 5.23.1; see the
// design doc's "Verified osquery behavior"):
//
//   - profile: EQUALS only; absent defaults to baseline. Any other
//     operator is an error — ignoring it would scan baseline and let
//     SQLite post-filter the result to zero rows, silently.
//   - root: EQUALS values become explicit scan roots. Other operators
//     are ignored here on purpose: the default-profile roots are
//     scanned and SQLite post-filters the rows (`root LIKE '/Users/%'`).
//   - IN (...) and OR'd equalities arrive as one Generate call per
//     value on current osquery; multiple values per call are handled
//     anyway.
func Generate(scan ScanFunc) osqtable.GenerateFunc {
	return func(ctx context.Context, qc osqtable.QueryContext) ([]map[string]string, error) {
		profile, err := profileFromConstraints(qc)
		if err != nil {
			return nil, err
		}
		var explicit []string
		if cl, ok := qc.Constraints["root"]; ok {
			for _, c := range cl.Constraints {
				if c.Operator == osqtable.OperatorEquals {
					explicit = append(explicit, c.Expression)
				}
			}
		}

		out, err := scan(ctx, profile, explicit)
		if err != nil {
			return nil, fmt.Errorf("beagle_packages: %w", err)
		}

		records := filterByEcosystem(out.Records, qc)
		rootFor := newRootPathLookup(out.Roots)
		rows := make([]map[string]string, 0, len(records))
		for _, r := range records {
			rows = append(rows, recordRow(r, rootFor(r.SourceFile), out.Truncated))
		}
		return rows, nil
	}
}

func profileFromConstraints(qc osqtable.QueryContext) (string, error) {
	cl, ok := qc.Constraints["profile"]
	if !ok {
		return model.ProfileBaseline, nil
	}
	profile := ""
	for _, c := range cl.Constraints {
		if c.Operator != osqtable.OperatorEquals {
			return "", fmt.Errorf(
				"beagle_packages: profile only supports '=' (got operator %d); use profile = 'baseline' | 'project' | 'deep'",
				c.Operator)
		}
		if profile != "" && c.Expression != profile {
			return "", fmt.Errorf(
				"beagle_packages: conflicting profile values %q and %q; use one profile per query",
				profile, c.Expression)
		}
		profile = c.Expression
	}
	if profile == "" {
		return model.ProfileBaseline, nil
	}
	return profile, nil
}

// newRootPathLookup maps a file path to the path of the longest
// configured root that contains it — the same matching rule
// scanner.newRootKindLookup applies for root_kind, but returning the
// root's path. Matching uses cleaned absolute paths; the returned value
// is the root's path byte-for-byte as configured, because SQLite
// re-verifies WHERE predicates on returned rows and a normalized value
// no longer matches a constraint like root = '/path/' (trailing slash).
func newRootPathLookup(roots []scanner.Root) func(string) string {
	type entry struct {
		cleaned  string
		verbatim string
	}
	entries := make([]entry, 0, len(roots))
	for _, r := range roots {
		if r.Path == "" {
			continue
		}
		p, err := filepath.Abs(r.Path)
		if err != nil {
			p = r.Path
		}
		entries = append(entries, entry{cleaned: filepath.Clean(p), verbatim: r.Path})
	}
	return func(path string) string {
		if path == "" {
			return ""
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		abs = filepath.Clean(abs)
		bestLen := -1
		best := ""
		for _, e := range entries {
			if abs == e.cleaned || strings.HasPrefix(abs, e.cleaned+string(filepath.Separator)) {
				if len(e.cleaned) > bestLen {
					bestLen = len(e.cleaned)
					best = e.verbatim
				}
			}
		}
		return best
	}
}

// recordRow maps one package record to an osquery row. osquery-go rows
// are map[string]string; an empty string in an INTEGER column is
// coerced to SQL NULL by osquery core (verified on 5.23.1), which is
// how direct_dependency preserves its tri-state.
func recordRow(r model.Record, rootPath string, truncated bool) map[string]string {
	directDep := ""
	if r.DirectDependency != nil {
		if *r.DirectDependency {
			directDep = "1"
		} else {
			directDep = "0"
		}
	}
	lifecycle := ""
	if len(r.LifecycleScripts) > 0 {
		if b, err := json.Marshal(r.LifecycleScripts); err == nil {
			lifecycle = string(b)
		}
	}
	return map[string]string{
		"endpoint_username":     r.Endpoint.Username,
		"ecosystem":             r.Ecosystem,
		"package_name":          r.PackageName,
		"normalized_name":       r.NormalizedName,
		"version":               r.Version,
		"root_kind":             r.RootKind,
		"install_scope":         r.InstallScope,
		"package_manager":       r.PackageManager,
		"source_type":           r.SourceType,
		"source_file":           r.SourceFile,
		"confidence":            r.Confidence,
		"requested_spec":        r.RequestedSpec,
		"server_name":           r.ServerName,
		"direct_dependency":     directDep,
		"has_lifecycle_scripts": boolCell(r.HasLifecycleScripts),
		"lifecycle_scripts":     lifecycle,
		"profile":               r.Profile,
		"root":                  rootPath,
		"scan_truncated":        boolCell(truncated),
	}
}

func boolCell(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

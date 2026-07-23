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
	"sort"
	"strconv"
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

// DistinctColumns returns the beagle_distinct_packages schema: the
// beagle_packages columns except source_file (the field records are
// deduplicated on), plus install_count and a source_files JSON array.
// profile/root keep their hidden+index options, inherited from Columns.
func DistinctColumns() []osqtable.ColumnDefinition {
	base := Columns()
	cols := make([]osqtable.ColumnDefinition, 0, len(base)+1)
	for _, c := range base {
		if c.Name == "source_file" {
			continue
		}
		cols = append(cols, c)
	}
	return append(cols,
		osqtable.IntegerColumn("install_count"),
		osqtable.TextColumn("source_files"),
	)
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

// dedupeRows collapses records that are identical except for their source
// location into one beagle_distinct_packages row. Records are grouped by
// every distinct-table column (the beagle_packages row minus source_file);
// each group yields one row carrying install_count (the number of distinct
// source files) and source_files (their sorted, de-duplicated JSON array).
// Groups are emitted sorted by key so output is deterministic.
func dedupeRows(records []model.Record, rootFor func(string) string, truncated bool) []map[string]string {
	type group struct {
		row   map[string]string
		files []string
	}
	groups := make(map[string]*group)
	for _, r := range records {
		row := recordRow(r, rootFor(r.SourceFile), truncated)
		sf := row["source_file"]
		delete(row, "source_file")
		key := distinctKey(row)
		g := groups[key]
		if g == nil {
			g = &group{row: row}
			groups[key] = g
		}
		g.files = append(g.files, sf)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]map[string]string, 0, len(groups))
	for _, k := range keys {
		g := groups[k]
		files := sortedUnique(g.files)
		g.row["install_count"] = strconv.Itoa(len(files))
		sources := "[]"
		if b, err := json.Marshal(files); err == nil {
			sources = string(b)
		}
		g.row["source_files"] = sources
		rows = append(rows, g.row)
	}
	return rows
}

// distinctKey builds a collision-free grouping key from a row map: two
// records collide only when every column value is identical. Each column
// name and value is length-prefixed (decimal byte length, ':', then the
// bytes) over the sorted column names, so the encoding is injective even
// when values carry arbitrary bytes. Package metadata comes from untrusted
// manifests and can contain embedded NUL or delimiter bytes, so a plain
// separator-joined key would be forgeable.
func distinctKey(row map[string]string) string {
	names := make([]string, 0, len(row))
	for k := range row {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		v := row[k]
		fmt.Fprintf(&b, "%d:%s%d:%s", len(k), k, len(v), v)
	}
	return b.String()
}

// sortedUnique returns the input sorted with adjacent duplicates removed,
// without mutating the caller's slice.
func sortedUnique(in []string) []string {
	if len(in) < 2 {
		return in
	}
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	out := cp[:1]
	for _, s := range cp[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// scanForQuery resolves the profile and root constraints, runs (or serves
// from cache) the scan, and applies the ecosystem filter. It is shared by
// both tables; table is used only to prefix errors. It returns the
// filtered records, the enclosing-root lookup for row mapping, and the
// scan's truncated flag.
//
// Constraint semantics (verified against osqueryd 5.23.1; see the design
// doc's "Verified osquery behavior"):
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
func scanForQuery(
	ctx context.Context, scan ScanFunc, qc osqtable.QueryContext, table string,
) ([]model.Record, func(string) string, bool, error) {
	profile, err := profileFromConstraints(qc, table)
	if err != nil {
		return nil, nil, false, err
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
		return nil, nil, false, fmt.Errorf("%s: %w", table, err)
	}
	return filterByEcosystem(out.Records, qc), newRootPathLookup(out.Roots), out.Truncated, nil
}

// Generate maps the constrained scan's records to beagle_packages rows.
func Generate(scan ScanFunc) osqtable.GenerateFunc {
	return func(ctx context.Context, qc osqtable.QueryContext) ([]map[string]string, error) {
		records, rootFor, truncated, err := scanForQuery(ctx, scan, qc, "beagle_packages")
		if err != nil {
			return nil, err
		}
		rows := make([]map[string]string, 0, len(records))
		for _, r := range records {
			rows = append(rows, recordRow(r, rootFor(r.SourceFile), truncated))
		}
		return rows, nil
	}
}

// GenerateDistinct maps the constrained scan's records to
// beagle_distinct_packages rows, collapsing install-location duplicates.
func GenerateDistinct(scan ScanFunc) osqtable.GenerateFunc {
	return func(ctx context.Context, qc osqtable.QueryContext) ([]map[string]string, error) {
		records, rootFor, truncated, err := scanForQuery(ctx, scan, qc, "beagle_distinct_packages")
		if err != nil {
			return nil, err
		}
		return dedupeRows(records, rootFor, truncated), nil
	}
}

func profileFromConstraints(qc osqtable.QueryContext, table string) (string, error) {
	cl, ok := qc.Constraints["profile"]
	if !ok {
		return model.ProfileBaseline, nil
	}
	profile := ""
	for _, c := range cl.Constraints {
		if c.Operator != osqtable.OperatorEquals {
			return "", fmt.Errorf(
				"%s: profile only supports '=' (got operator %d); use profile = 'baseline' | 'project' | 'deep'",
				table, c.Operator)
		}
		if profile != "" && c.Expression != profile {
			return "", fmt.Errorf(
				"%s: conflicting profile values %q and %q; use one profile per query",
				table, profile, c.Expression)
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
		// Record source paths are already absolute and clean; Abs is a
		// Getwd syscall plus an allocation that is only needed for the
		// rare relative path.
		abs := path
		if !filepath.IsAbs(abs) {
			a, err := filepath.Abs(abs)
			if err != nil {
				a = abs
			}
			abs = filepath.Clean(a)
		}
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

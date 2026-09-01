package table

import "context"

// colsUsedSet is the set of columns one query reads, as reported by
// osquery's colsUsed field. A nil set means the query context carried no
// colsUsed at all and every column must be returned; an empty non-nil
// set is a real answer — a bare count(*) reads no columns — and yields
// rows with no cells.
type colsUsedSet map[string]struct{}

type colsUsedKey struct{}

// WithColsUsed returns ctx carrying the columns a query reads. The
// caller is the extension's plugin wrapper (osquery/colsused.go), which
// recovers the field osquery-go drops. Call it only when osquery
// actually sent colsUsed: an attached set always projects, and cols=nil
// attaches the empty set rather than disabling projection.
func WithColsUsed(ctx context.Context, cols []string) context.Context {
	set := make(colsUsedSet, len(cols))
	for _, c := range cols {
		set[c] = struct{}{}
	}
	return context.WithValue(ctx, colsUsedKey{}, set)
}

// colsUsedFrom returns the projection set attached to ctx, or nil when
// there is none.
func colsUsedFrom(ctx context.Context) colsUsedSet {
	set, _ := ctx.Value(colsUsedKey{}).(colsUsedSet)
	return set
}

// projectRow deletes the cells the query will not read. It mutates row
// in place; every caller builds the map per query, so no other query or
// the cached scan outcome can observe it.
//
// Projecting to colsUsed is safe because osquery includes every column a
// query touches, not only the selected ones: constrained columns (hidden
// ones like profile and root included) and ORDER BY columns are all
// listed. Verified against osqueryd 5.23.1, see the design record. That
// matters because SQLite re-verifies WHERE predicates against the rows
// the extension returns — dropping a cell a predicate reads would
// silently discard every row rather than error.
func projectRow(row map[string]string, cols colsUsedSet) {
	if cols == nil {
		return
	}
	for name := range row {
		if _, ok := cols[name]; !ok {
			delete(row, name)
		}
	}
}

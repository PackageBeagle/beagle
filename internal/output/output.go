// Package output emits NDJSON inventory records, findings, and diagnostics.
//
// Records and findings go to the configured records writer (stdout by default).
// Diagnostics go to the configured diagnostics writer (stderr by default).
// The emitter deduplicates identical package records within a single run using
// the public package-record identity tuple represented by record_id.
// Findings are not deduplicated separately — they shadow their underlying
// package record, which already collapses duplicates.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/packagebeagle/beagle/internal/model"
)

// errNoRecordsWriter reports a call that needs the NDJSON records
// stream on a collector Emitter, which has no records writer.
func errNoRecordsWriter(what string) error {
	return fmt.Errorf("emit %s: this emitter collects package records in memory and has no records writer; construct it with output.New", what)
}

// StatsReporter reports transport-side counters that can be copied into
// scan_summary without exposing transport internals to the scanner.
type StatsReporter interface {
	Stats() SinkStats
}

// SinkStats carries best-effort sink-side delivery counters.
type SinkStats struct {
	HTTPBatchesAttempted int
	HTTPBatchesSucceeded int
	HTTPBatchesFailed    int
	HTTPLastStatus       int
}

type Emitter struct {
	records io.Writer
	diags   io.Writer
	runID   string

	mu   sync.Mutex
	enc  *json.Encoder
	denc *json.Encoder
	seen map[string]struct{}

	// collecting selects the in-memory mode built by NewCollector:
	// package records accumulate in collected instead of being encoded.
	collecting bool
	collected  []model.Record

	RecordsEmitted int
	Duplicates     int
	Diagnostics    int
}

func New(records, diags io.Writer, runID string) *Emitter {
	return &Emitter{
		records: records,
		diags:   diags,
		runID:   runID,
		enc:     json.NewEncoder(records),
		denc:    json.NewEncoder(diags),
		seen:    make(map[string]struct{}),
	}
}

// NewCollector returns an Emitter that accumulates package records in
// memory instead of encoding them, for consumers that want the records
// as values rather than as NDJSON. Findings and the scan summary are
// still encoded to the diagnostics writer's sibling record stream — a
// collector has no records writer, so callers that need those must use
// New instead; EmitFinding and EmitSummary report an error here rather
// than writing nowhere.
func NewCollector(diags io.Writer, runID string) *Emitter {
	return &Emitter{
		diags:      diags,
		runID:      runID,
		denc:       json.NewEncoder(diags),
		seen:       make(map[string]struct{}),
		collecting: true,
	}
}

// Collected returns the records accumulated by a collector Emitter, and
// whether this Emitter is one. Ownership of the slice passes to the
// caller; the Emitter must not be used afterward.
func (e *Emitter) Collected() ([]model.Record, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.collected, e.collecting
}

// ObservePackage reserves the package record's dedupe slot and returns the
// canonicalized record plus whether it is new for this run.
func (e *Emitter) ObservePackage(r model.Record) (model.Record, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.RecordType == "" {
		r.RecordType = model.RecordTypePackage
	}
	if r.RecordID == "" {
		r.RecordID = r.StableID()
	}
	// RecordID is the dedupe key: DedupKey() is defined as StableID(),
	// which is exactly what RecordID holds, so reusing it here saves a
	// second SHA-256 per record.
	if _, ok := e.seen[r.RecordID]; ok {
		e.Duplicates++
		return r, false
	}
	e.seen[r.RecordID] = struct{}{}
	return r, true
}

// EmitObservedPackage writes a package record that has already been
// canonicalized and reserved via ObservePackage.
func (e *Emitter) EmitObservedPackage(r model.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.RecordsEmitted++
	if e.collecting {
		e.collected = append(e.collected, r)
		return nil
	}
	return e.enc.Encode(r)
}

// Emit writes a record unless an identical one has already been written.
// The returned bool reports whether the record was actually written
// (true) or suppressed as a duplicate (false). The error is non-nil only
// when the encoder itself failed.
func (e *Emitter) Emit(r model.Record) (bool, error) {
	r, ok := e.ObservePackage(r)
	if !ok {
		return false, nil
	}
	return true, e.EmitObservedPackage(r)
}

// EmitFinding writes one finding record to the records sink. Findings
// are not deduped at this layer — they ride on their underlying package
// record, which is already deduped.
func (e *Emitter) EmitFinding(f model.Finding) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.collecting {
		return errNoRecordsWriter("finding")
	}
	if f.RecordType == "" {
		f.RecordType = model.RecordTypeFinding
	}
	if f.RecordID == "" {
		f.RecordID = f.StableID()
	}
	return e.enc.Encode(f)
}

// EmitSummary writes a single scan_summary record to the records sink.
// It is written through the same encoder so it shares ordering and
// transport guarantees with package and finding records.
func (e *Emitter) EmitSummary(s model.ScanSummary) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.collecting {
		return errNoRecordsWriter("scan summary")
	}
	if s.RecordType == "" {
		s.RecordType = model.RecordTypeScanSummary
	}
	if s.RecordID == "" {
		s.RecordID = s.StableID()
	}
	return e.enc.Encode(s)
}

func (e *Emitter) Diag(level, path, msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Diagnostics++
	d := model.Diagnostic{
		RecordType: model.RecordTypeDiagnostic,
		RunID:      e.runID,
		Time:       time.Now().UTC().Format(time.RFC3339Nano),
		Level:      level,
		Path:       path,
		Message:    msg,
	}
	d.RecordID = d.StableID()
	_ = e.denc.Encode(d)
}

// Close flushes the records writer if it implements io.Closer. The
// diagnostics writer is intentionally left open; callers manage stderr.
func (e *Emitter) Close() error {
	if c, ok := e.records.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// SinkStats returns transport counters if the records writer exposes them.
func (e *Emitter) SinkStats() SinkStats {
	if s, ok := e.records.(StatsReporter); ok {
		return s.Stats()
	}
	return SinkStats{}
}

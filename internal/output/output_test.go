package output

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestEmitterDedupsWithinRun(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	rec := model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/p/package-lock.json",
	}
	if _, err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}
	if e.RecordsEmitted != 1 || e.Duplicates != 1 {
		t.Fatalf("emit=%d dup=%d", e.RecordsEmitted, e.Duplicates)
	}
	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Fatalf("want one NDJSON line, got %d", got)
	}
}

type closableBuf struct {
	bytes.Buffer
	closed bool
}

func (c *closableBuf) Close() error { c.closed = true; return nil }

func TestEmitterCloseClosesUnderlyingWriter(t *testing.T) {
	cb := &closableBuf{}
	e := New(cb, io.Discard, "run-1")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !cb.closed {
		t.Fatal("expected underlying writer to be closed")
	}
}

func TestEmitterCloseNoopOnPlainWriter(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEmitDefaultsRecordTypeToPackage(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	rec := model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/p/package-lock.json",
	}
	if _, err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["record_type"] != model.RecordTypePackage {
		t.Fatalf("record_type = %v, want %q", got["record_type"], model.RecordTypePackage)
	}
	if got["record_id"] == "" {
		t.Fatalf("record_id missing from emitted package record: %v", got)
	}
}

func TestEmitSummaryWritesScanSummaryRecord(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	s := model.ScanSummary{
		SchemaVersion: model.SchemaVersion,
		ScannerName:   model.ScannerName,
		RunID:         "run-1",
		Status:        model.ScanStatusComplete,
	}
	if err := e.EmitSummary(s); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["record_type"] != model.RecordTypeScanSummary {
		t.Fatalf("record_type = %v, want %q", got["record_type"], model.RecordTypeScanSummary)
	}
	if got["status"] != model.ScanStatusComplete {
		t.Fatalf("status = %v, want %q", got["status"], model.ScanStatusComplete)
	}
	if got["record_id"] == "" {
		t.Fatalf("record_id missing from summary: %v", got)
	}
	// EmitSummary should not bump the records dedup counter.
	if e.RecordsEmitted != 0 {
		t.Fatalf("RecordsEmitted=%d, want 0 (summary is not a package record)", e.RecordsEmitted)
	}
}

func TestObservePackageDedupsWithoutWriting(t *testing.T) {
	e := New(io.Discard, io.Discard, "run-1")
	rec := model.Record{
		Profile:        model.ProfileBaseline,
		Ecosystem:      model.EcosystemMCP,
		NormalizedName: "mcp-server-time",
		SourceType:     "mcp-config",
		SourceFile:     "/x/mcp.json",
		ServerName:     "time",
	}
	observed, ok := e.ObservePackage(rec)
	if !ok {
		t.Fatal("first observation should not dedup")
	}
	if observed.RecordID == "" {
		t.Fatal("observed record should have record_id")
	}
	if _, ok := e.ObservePackage(rec); ok {
		t.Fatal("second observation should dedup")
	}
	if e.Duplicates != 1 {
		t.Fatalf("Duplicates=%d, want 1", e.Duplicates)
	}
	if e.RecordsEmitted != 0 {
		t.Fatalf("RecordsEmitted=%d, want 0 before write", e.RecordsEmitted)
	}
}

func TestCollectorAccumulatesRecordsInsteadOfEncoding(t *testing.T) {
	e := NewCollector(io.Discard, "run-1")
	dep := true
	rec := model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/p/package-lock.json",
		DirectDependency: &dep, LifecycleScripts: []string{"postinstall"},
	}
	other := rec
	other.NormalizedName = "right-pad"

	for _, r := range []model.Record{rec, rec, other} {
		if _, err := e.Emit(r); err != nil {
			t.Fatal(err)
		}
	}

	got, ok := e.Collected()
	if !ok {
		t.Fatal("Collected reported a non-collector emitter")
	}
	if len(got) != 2 {
		t.Fatalf("collected %d records, want 2 (one deduped)", len(got))
	}
	if e.RecordsEmitted != 2 || e.Duplicates != 1 {
		t.Fatalf("emit=%d dup=%d", e.RecordsEmitted, e.Duplicates)
	}
	// Values survive as values: no JSON round-trip to flatten the
	// tri-state pointer or the slice.
	if got[0].DirectDependency == nil || !*got[0].DirectDependency {
		t.Fatal("direct_dependency should still be true")
	}
	if len(got[0].LifecycleScripts) != 1 || got[0].LifecycleScripts[0] != "postinstall" {
		t.Fatalf("lifecycle_scripts = %v", got[0].LifecycleScripts)
	}
	if got[0].RecordType != model.RecordTypePackage || got[0].RecordID == "" {
		t.Fatalf("record not canonicalized: %+v", got[0])
	}
}

func TestCollectorRejectsFindingsAndSummary(t *testing.T) {
	e := NewCollector(io.Discard, "run-1")
	if err := e.EmitFinding(model.Finding{}); err == nil {
		t.Fatal("EmitFinding on a collector should error, not write nowhere")
	}
	if err := e.EmitSummary(model.ScanSummary{}); err == nil {
		t.Fatal("EmitSummary on a collector should error, not write nowhere")
	}
}

func TestNewIsNotACollector(t *testing.T) {
	e := New(io.Discard, io.Discard, "run-1")
	if got, ok := e.Collected(); ok || got != nil {
		t.Fatalf("New emitter reported as collector (records=%v)", got)
	}
}

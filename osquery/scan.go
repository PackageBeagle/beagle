package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/packagebeagle/beagle/internal/endpoint"
	"github.com/packagebeagle/beagle/internal/model"
	"github.com/packagebeagle/beagle/internal/output"
	"github.com/packagebeagle/beagle/internal/roots"
	"github.com/packagebeagle/beagle/internal/scanner"
	beagletable "github.com/packagebeagle/beagle/osquery/table"
)

// maxFileSize caps how many bytes the scanner reads from any single
// metadata file, matching the CLI's --max-file-size default. It must
// never be zero: fsread.Bounded treats <= 0 as unbounded, which is a
// memory hazard in a resident extension reading attacker-plantable
// files.
const maxFileSize = 5 * 1024 * 1024

// maxConcurrentScans bounds simultaneous filesystem walks. root is a
// query-controllable input, so every distinct value is a cache miss;
// MaxDuration bounds one scan, not N.
const maxConcurrentScans = 2

type bridgeConfig struct {
	RootsOpts roots.Opts
	DeviceID  string
	// MaxDurationOverride, when > 0, overrides the per-profile scan
	// budget defaults (BEAGLE_MAX_DURATION). 0 means "use scanBudget's
	// per-profile default".
	MaxDurationOverride time.Duration
	MaxFileSize         int64
	CacheTTL            time.Duration
	// Diags receives scanner diagnostics and roots.Resolve notes
	// (extension stderr in production, io.Discard in tests).
	Diags io.Writer
}

// scanBudget returns the MaxDuration to apply for profile: override if
// set, else the per-profile default (baseline 30s, project 60s, deep
// 120s — a deep incident sweep needs more time than a global 30s
// default would allow). An unrecognized profile returns the baseline
// default; roots.Resolve rejects unknown profiles before this matters.
func scanBudget(profile string, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	switch profile {
	case model.ProfileProject:
		return 60 * time.Second
	case model.ProfileDeep:
		return 120 * time.Second
	default:
		return 30 * time.Second
	}
}

// scanBridge drives scanner.Run through the in-memory emitter and
// serves results through the TTL cache. It makes no internal/ changes:
// records are decoded back from the NDJSON the emitter just wrote —
// the deliberate phase-1 tradeoff recorded in the design doc.
type scanBridge struct {
	cfg   bridgeConfig
	cache *scanCache
	sem   chan struct{}
}

func newScanBridge(cfg bridgeConfig) *scanBridge {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = maxFileSize
	}
	if cfg.Diags == nil {
		cfg.Diags = io.Discard
	}
	return &scanBridge{
		cfg:   cfg,
		cache: newScanCache(cfg.CacheTTL),
		sem:   make(chan struct{}, maxConcurrentScans),
	}
}

// Scan implements table.ScanFunc.
func (b *scanBridge) Scan(ctx context.Context, profile string, explicit []string) (beagletable.ScanOutcome, error) {
	key := cacheKey(profile, explicit)
	return b.cache.Do(key, func() (beagletable.ScanOutcome, error) {
		return b.scan(ctx, profile, explicit)
	})
}

// cacheKey is profile followed by the explicit roots sorted, each
// preceded by a NUL (NUL cannot appear in paths). A leading NUL per
// root, rather than a single joining separator, keeps zero explicit
// roots distinguishable from one empty-string root. Keyed on the
// pre-resolution inputs: resolution is deterministic for the life of
// the process.
func cacheKey(profile string, explicit []string) string {
	s := append([]string(nil), explicit...)
	sort.Strings(s)
	var b strings.Builder
	b.WriteString(profile)
	for _, r := range s {
		b.WriteByte(0)
		b.WriteString(r)
	}
	return b.String()
}

func (b *scanBridge) scan(ctx context.Context, profile string, explicit []string) (beagletable.ScanOutcome, error) {
	resolved, notes, err := roots.Resolve(profile, explicit, b.cfg.RootsOpts)
	if err != nil {
		return beagletable.ScanOutcome{}, err
	}

	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
	case <-ctx.Done():
		return beagletable.ScanOutcome{}, ctx.Err()
	}

	runID := newRunID()
	var buf bytes.Buffer
	emitter := output.New(&buf, b.cfg.Diags, runID)
	for _, n := range notes {
		emitter.Diag("info", "", n)
	}

	cfg := scanner.Config{
		Profile:     profile,
		Roots:       resolved,
		MaxFileSize: b.cfg.MaxFileSize,
		MaxDuration: scanBudget(profile, b.cfg.MaxDurationOverride),
		BaseRecord: model.Record{
			RecordType:     model.RecordTypePackage,
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: currentVersion(),
			RunID:          runID,
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
			Endpoint:       endpoint.Current(b.cfg.DeviceID),
			Profile:        profile,
		},
		Emitter: emitter,
	}
	res, runErr := scanner.Run(ctx, cfg)
	if runErr != nil {
		emitter.Diag("error", "", runErr.Error())
	}

	records, decErr := decodeRecords(&buf)
	if decErr != nil {
		return beagletable.ScanOutcome{}, fmt.Errorf("decode scan records: %w", decErr)
	}
	if runErr != nil && len(records) == 0 {
		return beagletable.ScanOutcome{}, runErr
	}
	return beagletable.ScanOutcome{
		Records: records,
		Roots:   resolved,
		// A run error with partial records is served like a truncated
		// scan: rows flow, scan_truncated=1, nothing cached.
		Truncated: res.Truncated || runErr != nil,
	}, nil
}

// decodeRecords reads the emitter's NDJSON back into records, keeping
// only package records for safety (nothing else is written through
// this path today).
func decodeRecords(r io.Reader) ([]model.Record, error) {
	dec := json.NewDecoder(r)
	var out []model.Record
	for {
		var rec model.Record
		if err := dec.Decode(&rec); err == io.EOF {
			return out, nil
		} else if err != nil {
			return nil, err
		}
		if rec.RecordType == model.RecordTypePackage {
			out = append(out, rec)
		}
	}
}

func newRunID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

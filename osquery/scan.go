package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// scanBudget returns the MaxDuration to apply for profile: the override
// if set, else the per-profile default below. Broader profiles get a
// larger budget, since a deep incident sweep cannot finish in the time
// a baseline scan needs. An unrecognized profile returns the baseline
// default; roots.Resolve rejects unknown profiles before this matters.
func scanBudget(profile string, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	switch profile {
	case model.ProfileProject:
		return 300 * time.Second
	case model.ProfileDeep:
		return 300 * time.Second
	default:
		return 120 * time.Second
	}
}

// scanBridge drives scanner.Run through a collecting emitter and serves
// results through the TTL cache. The emitter hands back records as
// values, so the extension never encodes and re-decodes NDJSON to
// produce rows.
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
func (b *scanBridge) Scan(
	ctx context.Context, profile string, explicit, excludes []string,
) (beagletable.ScanOutcome, error) {
	key := cacheKey(profile, explicit, excludes)
	return b.cache.Do(key, func() (beagletable.ScanOutcome, error) {
		return b.scan(ctx, profile, explicit, excludes)
	})
}

// cacheKey is profile, then each explicit root sorted, then each
// exclude pattern sorted, every entry preceded by a NUL and a tag byte
// ('r' root, 'x' exclude). NUL cannot appear in paths and the table
// rejects it in an exclude, so the encoding is injective: a leading NUL
// per entry keeps zero entries distinguishable from one empty entry,
// and the tag keeps an exclude from reading as a root. Keyed on the
// pre-resolution inputs: resolution is deterministic for the life of
// the process.
func cacheKey(profile string, explicit, excludes []string) string {
	var b strings.Builder
	b.WriteString(profile)
	for _, part := range []struct {
		tag  byte
		vals []string
	}{{'r', explicit}, {'x', excludes}} {
		s := append([]string(nil), part.vals...)
		sort.Strings(s)
		for _, v := range s {
			b.WriteByte(0)
			b.WriteByte(part.tag)
			b.WriteString(v)
		}
	}
	return b.String()
}

func (b *scanBridge) scan(
	ctx context.Context, profile string, explicit, excludes []string,
) (beagletable.ScanOutcome, error) {
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
	emitter := output.NewCollector(b.cfg.Diags, runID)
	for _, n := range notes {
		emitter.Diag("info", "", n)
	}

	cfg := scanner.Config{
		Profile:         profile,
		Roots:           resolved,
		ExcludePatterns: excludes,
		MaxFileSize:     b.cfg.MaxFileSize,
		MaxDuration:     scanBudget(profile, b.cfg.MaxDurationOverride),
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

	records, _ := emitter.Collected()
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

func newRunID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

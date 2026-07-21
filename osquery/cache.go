package main

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	beagletable "github.com/packagebeagle/beagle/osquery/table"
)

// scanCache is a TTL cache with per-key singleflight: concurrent
// callers for the same key wait for and share one scan, while scans
// for different keys proceed independently (the mutex covers only map
// access, never a scan). Truncated outcomes are returned to their
// callers but never stored, so the next query retries instead of
// serving partial-as-complete for the TTL.
type scanCache struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]cacheEntry
	group   singleflight.Group
}

type cacheEntry struct {
	outcome  beagletable.ScanOutcome
	storedAt time.Time
}

// newScanCache returns a cache holding entries for ttl. ttl <= 0
// disables storage entirely; in-flight deduplication still applies.
func newScanCache(ttl time.Duration) *scanCache {
	return &scanCache{ttl: ttl, entries: make(map[string]cacheEntry)}
}

func (c *scanCache) lookup(key string) (beagletable.ScanOutcome, bool) {
	if c.ttl <= 0 {
		return beagletable.ScanOutcome{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.storedAt) >= c.ttl {
		return beagletable.ScanOutcome{}, false
	}
	return e.outcome, true
}

func (c *scanCache) store(key string, out beagletable.ScanOutcome) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry{outcome: out, storedAt: time.Now()}
	c.mu.Unlock()
}

// Do returns the cached outcome for key or runs fn once, sharing the
// result with concurrent callers of the same key.
func (c *scanCache) Do(key string, fn func() (beagletable.ScanOutcome, error)) (beagletable.ScanOutcome, error) {
	if out, ok := c.lookup(key); ok {
		return out, nil
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		// Re-check under the flight: a previous flight may have stored
		// the entry between our miss and this call.
		if out, ok := c.lookup(key); ok {
			return out, nil
		}
		out, err := fn()
		if err != nil {
			return beagletable.ScanOutcome{}, err
		}
		if !out.Truncated {
			c.store(key, out)
		}
		return out, nil
	})
	if err != nil {
		return beagletable.ScanOutcome{}, err
	}
	return v.(beagletable.ScanOutcome), nil
}

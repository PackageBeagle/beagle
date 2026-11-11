package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/packagebeagle/beagle/internal/model"
	beagletable "github.com/packagebeagle/beagle/osquery/table"
)

func outcome(name string) beagletable.ScanOutcome {
	return beagletable.ScanOutcome{Records: []model.Record{{PackageName: name}}}
}

func TestCacheHitWithinTTL(t *testing.T) {
	c := newScanCache(time.Minute)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		return outcome("x"), nil
	}
	for i := 0; i < 3; i++ {
		out, err := c.Do("k", fn)
		if err != nil {
			t.Fatal(err)
		}
		if out.Records[0].PackageName != "x" {
			t.Fatalf("wrong outcome: %+v", out)
		}
	}
	if calls != 1 {
		t.Fatalf("scan ran %d times, want 1", calls)
	}
}

func TestCacheMissAfterExpiry(t *testing.T) {
	c := newScanCache(10 * time.Millisecond)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		return outcome("x"), nil
	}
	if _, err := c.Do("k", fn); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Do("k", fn); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("scan ran %d times, want 2 after TTL expiry", calls)
	}
}

func TestCachePerKeyIsolation(t *testing.T) {
	c := newScanCache(time.Minute)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		return outcome("x"), nil
	}
	if _, err := c.Do("baseline\x00/a", fn); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("baseline\x00/b", fn); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("scan ran %d times, want 2 (distinct keys must not collide)", calls)
	}
}

func TestCacheConcurrentSameKeySharesOneScan(t *testing.T) {
	c := newScanCache(time.Minute)
	var calls int32
	release := make(chan struct{})
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return outcome("x"), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Do("k", fn); err != nil {
				t.Error(err)
			}
		}()
	}
	// Let the goroutines pile onto the flight before releasing it.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls != 1 {
		t.Fatalf("scan ran %d times, want 1 shared flight", calls)
	}
}

// TestCacheDifferentKeysDoNotBlock pins the property a naive global
// mutex loses: a slow scan for key A must not stall key B.
func TestCacheDifferentKeysDoNotBlock(t *testing.T) {
	c := newScanCache(time.Minute)
	blockA := make(chan struct{})
	aStarted := make(chan struct{})
	go func() {
		_, _ = c.Do("a", func() (beagletable.ScanOutcome, error) {
			close(aStarted)
			<-blockA
			return outcome("a"), nil
		})
	}()
	<-aStarted

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := c.Do("b", func() (beagletable.ScanOutcome, error) {
			return outcome("b"), nil
		}); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("query for key b blocked behind in-flight scan for key a")
	}
	close(blockA)
}

func TestCacheTruncatedNotStored(t *testing.T) {
	c := newScanCache(time.Minute)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		out := outcome("x")
		out.Truncated = true
		return out, nil
	}
	out, err := c.Do("k", fn)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated {
		t.Fatal("truncated outcome must still be returned to the caller")
	}
	if _, err := c.Do("k", fn); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("scan ran %d times, want 2 (truncated results must not be cached)", calls)
	}
}

func TestCacheErrorNotStored(t *testing.T) {
	c := newScanCache(time.Minute)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		return beagletable.ScanOutcome{}, errTest
	}
	if _, err := c.Do("k", fn); err == nil {
		t.Fatal("want error")
	}
	if _, err := c.Do("k", fn); err == nil {
		t.Fatal("want error on retry too")
	}
	if calls != 2 {
		t.Fatalf("scan ran %d times, want 2 (errors must not be cached)", calls)
	}
}

func TestCacheTTLZeroDisablesStorage(t *testing.T) {
	c := newScanCache(0)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		return outcome("x"), nil
	}
	if _, err := c.Do("k", fn); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("k", fn); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("scan ran %d times, want 2 with caching disabled", calls)
	}
}

var errTest = &testError{}

type testError struct{}

func (*testError) Error() string { return "test scan failure" }

func storedKeys(c *scanCache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func scanNamed(name string) func() (beagletable.ScanOutcome, error) {
	return func() (beagletable.ScanOutcome, error) { return outcome(name), nil }
}

// TestCacheExpiredEntriesRemovedOnStore pins the leak fix: an expired
// entry must not keep its records in memory once another key is stored.
func TestCacheExpiredEntriesRemovedOnStore(t *testing.T) {
	c := newScanCache(10 * time.Millisecond)
	for _, k := range []string{"a", "b", "c"} {
		if _, err := c.Do(k, scanNamed(k)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Do("d", scanNamed("d")); err != nil {
		t.Fatal(err)
	}
	if n := storedKeys(c); n != 1 {
		t.Fatalf("cache holds %d entries after expiry, want 1 (only the fresh key)", n)
	}
}

// TestCacheExpiredEntriesRemovedOnLookup covers a query whose scan
// errors or truncates (so nothing is stored): the lookup alone must
// still drop expired entries.
func TestCacheExpiredEntriesRemovedOnLookup(t *testing.T) {
	c := newScanCache(10 * time.Millisecond)
	for _, k := range []string{"a", "b"} {
		if _, err := c.Do(k, scanNamed(k)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	_, _ = c.Do("e", func() (beagletable.ScanOutcome, error) { return beagletable.ScanOutcome{}, errTest })
	if n := storedKeys(c); n != 0 {
		t.Fatalf("cache holds %d entries after expiry, want 0", n)
	}
}

// TestCacheFreshEntriesSurviveEviction guards against over-eager
// eviction: entries inside the TTL stay and still serve hits.
func TestCacheFreshEntriesSurviveEviction(t *testing.T) {
	c := newScanCache(time.Minute)
	var calls int32
	fn := func() (beagletable.ScanOutcome, error) {
		atomic.AddInt32(&calls, 1)
		return outcome("a"), nil
	}
	if _, err := c.Do("a", fn); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("b", scanNamed("b")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("a", fn); err != nil {
		t.Fatal(err)
	}
	if n := storedKeys(c); n != 2 {
		t.Fatalf("cache holds %d entries, want 2 fresh entries", n)
	}
	if calls != 1 {
		t.Fatalf("scan for a ran %d times, want 1 (fresh entry evicted)", calls)
	}
}

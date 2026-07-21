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

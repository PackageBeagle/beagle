package main

import (
	"testing"
)

func TestRunSelftestSucceedsAndExitsZero(t *testing.T) {
	code := runSelftest([]string{"--quiet"})
	if code != 0 {
		t.Fatalf("runSelftest exit code = %d, want 0", code)
	}
}

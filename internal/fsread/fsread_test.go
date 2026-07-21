package fsread

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, size int) string {
	t.Helper()
	data := strings.Repeat("a", size)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBounded_ExactlyAtLimit_OK(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, "f.txt"), 10)

	data, err := Bounded(path, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 10 {
		t.Fatalf("got %d bytes, want 10", len(data))
	}
}

func TestBounded_OneByteOver_Error(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, "f.txt"), 11)

	var diags []string
	_, err := Bounded(path, 10, func(level, p, msg string) {
		diags = append(diags, level+":"+p+":"+msg)
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], "warn:") {
		t.Fatalf("expected one warn diag, got %v", diags)
	}
}

func TestBounded_NotRegularFile_Error(t *testing.T) {
	dir := t.TempDir()

	_, err := Bounded(dir, 1024, nil)
	if err == nil {
		t.Fatal("expected error for directory path, got nil")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestBounded_MissingFile_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.txt")

	_, err := Bounded(path, 1024, nil)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected a not-exist error, got: %v", err)
	}
}

func TestBounded_Unbounded_ReadsEverything(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, "f.txt"), 5000)

	data, err := Bounded(path, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 5000 {
		t.Fatalf("got %d bytes, want 5000", len(data))
	}
}

// TestReadCapped_EnforcesLimitDuringRead is the TOCTOU-enforcement test.
// Bounded's exported API is path-based: it stats the path first and takes a
// fast-rejection path when the stat size already exceeds maxSize. That fast
// path can't be exercised to prove the *read itself* is bounded, because a
// deterministic unit test can't reliably make a real file grow between the
// os.Open/Stat call and the io.ReadAll call inside the same function
// invocation (that race is exactly the TOCTOU bug, and asserting on it here
// would make this test flaky).
//
// Instead this calls the package-private readCapped directly with a plain
// io.Reader that yields more bytes than maxSize, bypassing any stat check
// entirely. This proves the enforcement lives in the LimitReader-bounded
// read path itself (readCapped), not merely in the pre-read stat
// comparison in Bounded — i.e. even a size that a stat check would have
// missed or lied about is still caught here.
func TestReadCapped_EnforcesLimitDuringRead(t *testing.T) {
	r := strings.NewReader(strings.Repeat("a", 15)) // 5 bytes over maxSize

	var diags []string
	_, err := readCapped(r, "fake/path", 10, func(level, p, msg string) {
		diags = append(diags, level+":"+p+":"+msg)
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], "warn:") {
		t.Fatalf("expected one warn diag, got %v", diags)
	}
}

func TestReadCapped_AtLimit_OK(t *testing.T) {
	r := strings.NewReader(strings.Repeat("a", 10))

	data, err := readCapped(r, "fake/path", 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 10 {
		t.Fatalf("got %d bytes, want 10", len(data))
	}
}

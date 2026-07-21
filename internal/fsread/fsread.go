// Package fsread provides a bounded file read shared by the ecosystem
// scanners: open a path, verify it is a regular file, and read at most
// maxSize bytes. Unlike a naive os.Stat size check followed by
// io.ReadAll, the read itself is capped with io.LimitReader so a file
// that grows between the stat and the read (a TOCTOU race) cannot
// produce an unbounded read.
package fsread

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Bounded reads the entire contents of the file at path, capped at maxSize
// bytes. maxSize <= 0 means unbounded (no cap applied). A path that is not
// a regular file (e.g. a directory) is rejected before any read is
// attempted.
//
// The stat size is checked first as a fast rejection for files that are
// already too large; the actual read is then bounded with
// io.LimitReader(f, maxSize+1) and the bytes read are checked again, so a
// file that grows after the stat call is still caught during the read
// rather than allowed to read unbounded.
//
// diag, if non-nil, is invoked with a "warn" level message when the size
// limit is exceeded, before the error is returned.
func Bounded(path string, maxSize int64, diag func(level, path, msg string)) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if maxSize <= 0 {
		return io.ReadAll(f)
	}
	if info.Size() > maxSize {
		return nil, tooLarge(path, info.Size(), maxSize, diag)
	}
	return readCapped(f, path, maxSize, diag)
}

// readCapped reads r through io.LimitReader(r, maxSize+1) and re-checks the
// actual byte count against maxSize. This is the enforcement point for the
// TOCTOU case: it does not trust the stat-based size Bounded already
// checked, so a reader that yields more than maxSize bytes is rejected here
// even when a prior size check would have missed it.
func readCapped(r io.Reader, path string, maxSize int64, diag func(level, path, msg string)) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, tooLarge(path, int64(len(data)), maxSize, diag)
	}
	return data, nil
}

func tooLarge(path string, size, maxSize int64, diag func(level, path, msg string)) error {
	if diag != nil {
		diag("warn", path, fmt.Sprintf("skipping: size %d exceeds max %d", size, maxSize))
	}
	return fmt.Errorf("file %s exceeds max size %d", path, maxSize)
}

package walk

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ValidateExcludePattern reports why p cannot be used as an exclude
// pattern, or nil when it can. A pattern is an absolute path glob whose
// components are matched one-for-one by filepath.Match, so `*` stands
// for exactly one path component: /Users/*/scripts skips the scripts
// directory in every home under /Users.
//
// `**` is refused rather than read as `*`, because it looks like it
// means something it does not. A bare `/` would exclude everything.
// Splitting a comma list is the caller's job; p is one pattern.
func ValidateExcludePattern(p string) error {
	switch {
	case p == "":
		return errors.New("exclude pattern is empty; use an absolute path glob such as /Users/*/scripts")
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("exclude pattern %q contains a NUL byte", p)
	case !filepath.IsAbs(p):
		return fmt.Errorf("exclude pattern %q must be an absolute path glob, e.g. /Users/*/scripts", p)
	case strings.Contains(p, "**"):
		return fmt.Errorf(
			"exclude pattern %q uses '**', which is not supported; '*' matches exactly one path component", p)
	}
	comps := splitPattern(p)
	if len(comps) == 0 {
		return fmt.Errorf("exclude pattern %q would exclude the whole filesystem", p)
	}
	for _, c := range comps {
		if _, err := filepath.Match(c, ""); err != nil {
			return fmt.Errorf("exclude pattern %q is malformed at %q: %w", p, c, err)
		}
	}
	return nil
}

// splitPattern cleans an absolute pattern and returns its components,
// or nil for the filesystem root.
func splitPattern(p string) []string {
	sep := string(filepath.Separator)
	clean := filepath.Clean(p)
	if clean == sep {
		return nil
	}
	return strings.Split(strings.TrimPrefix(clean, sep), sep)
}

// matchesPattern reports whether the leading components of the clean
// absolute path match pat one-for-one. A path with fewer components
// than pat never matches, so an ancestor of an excluded tree is still
// walked. It does not allocate.
func matchesPattern(pat []string, path string) bool {
	sep := string(filepath.Separator)
	rest := strings.TrimPrefix(path, sep)
	for _, pc := range pat {
		if rest == "" {
			return false
		}
		comp, tail, _ := strings.Cut(rest, sep)
		if ok, _ := filepath.Match(pc, comp); !ok {
			return false
		}
		rest = tail
	}
	return true
}

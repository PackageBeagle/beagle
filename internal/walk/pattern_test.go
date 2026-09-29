package walk

import (
	"strings"
	"testing"
)

func TestValidateExcludePatternAccepts(t *testing.T) {
	for _, p := range []string{
		"/Users/*/scripts",
		"/Users/*/scripts/",
		"/home/*/src/proj-*",
		"/Users/?/x",
		"/Users/[a-m]*/x",
		"/opt",
	} {
		if err := ValidateExcludePattern(p); err != nil {
			t.Errorf("ValidateExcludePattern(%q) = %v, want nil", p, err)
		}
	}
}

func TestValidateExcludePatternRejects(t *testing.T) {
	cases := []struct {
		pattern string
		want    string
	}{
		{"", "empty"},
		{"scripts", "absolute"},
		{"*/scripts", "absolute"},
		{"./x", "absolute"},
		{"/", "whole filesystem"},
		{"//", "whole filesystem"},
		{"/Users/**/scripts", "**"},
		{"/Users/[/x", "malformed"},
		{"/Users/x\\", "malformed"},
		{"/Users/\x00/x", "NUL"},
	}
	for _, c := range cases {
		err := ValidateExcludePattern(c.pattern)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ValidateExcludePattern(%q) = %v, want error containing %q", c.pattern, err, c.want)
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/Users/*/scripts", "/Users/s/scripts", true},
		// Leading components: anything beneath a match matches too, which
		// is what makes a root inside the tree yield nothing.
		{"/Users/*/scripts", "/Users/s/scripts/beagle", true},
		{"/Users/*/scripts/", "/Users/s/scripts", true},
		// * is exactly one component, never zero and never several.
		{"/Users/*/scripts", "/Users/scripts", false},
		{"/Users/*/scripts", "/Users/a/b/scripts", false},
		// Shallower than the pattern: an ancestor is never excluded.
		{"/Users/*/scripts", "/Users/s", false},
		{"/Users/*/scripts", "/Users", false},
		{"/Users/*/scripts", "/", false},
		// Component boundaries hold.
		{"/Users/*/scripts", "/Users/s/scripts2", false},
		{"/Users/*/proj-*", "/Users/s/proj-a", true},
		// Lexical and case-sensitive.
		{"/users/*/scripts", "/Users/s/scripts", false},
	}
	for _, c := range cases {
		if got := matchesPattern(splitPattern(c.pattern), c.path); got != c.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

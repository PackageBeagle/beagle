package roots

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// TestChromiumProfileDirsEnumeratesRealProfiles verifies that every
// subdirectory containing a Preferences file is treated as a profile,
// regardless of name — including Profile 10 and custom profile names
// that the old hardcoded Default/Profile-1..9 list could never match.
// Non-profile directories (no Preferences file) and stray regular files
// directly under the data dir are excluded.
func TestChromiumProfileDirsEnumeratesRealProfiles(t *testing.T) {
	base := t.TempDir()
	mustMkdir(t, filepath.Join(base, "Default"))
	mustWrite(t, filepath.Join(base, "Default", "Preferences"), "{}")
	mustMkdir(t, filepath.Join(base, "Profile 1"))
	mustWrite(t, filepath.Join(base, "Profile 1", "Preferences"), "{}")
	mustMkdir(t, filepath.Join(base, "Profile 10"))
	mustWrite(t, filepath.Join(base, "Profile 10", "Preferences"), "{}")
	mustMkdir(t, filepath.Join(base, "Custom Name"))
	mustWrite(t, filepath.Join(base, "Custom Name", "Preferences"), "{}")
	// Non-profile directory: no Preferences file.
	mustMkdir(t, filepath.Join(base, "Crashpad"))
	mustWrite(t, filepath.Join(base, "Crashpad", "settings.dat"), "x")
	// Stray regular file directly under the data dir.
	mustWrite(t, filepath.Join(base, "First Run"), "x")

	got := chromiumProfileDirs(base)
	want := []string{"Custom Name", "Default", "Profile 1", "Profile 10"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chromiumProfileDirs(%q) = %v, want %v", base, got, want)
	}
}

// TestChromiumProfileDirsNonexistentBase confirms a missing/unreadable
// data dir yields no profiles and no error escape, matching the
// pre-existing behavior of the candidate-building path (nonexistent
// roots are simply absent from the result, not a hard failure).
func TestChromiumProfileDirsNonexistentBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "does-not-exist")
	got := chromiumProfileDirs(base)
	if got != nil {
		t.Errorf("chromiumProfileDirs(%q) = %v, want nil", base, got)
	}
}

// TestBrowserExtensionCandidateRootsEnumeratesChromiumProfiles is an
// end-to-end check through the public entry point: a synthetic home
// directory with a Chrome data dir laid out at the real OS-specific
// path is given Default, Profile 1, and Profile 10, and the resulting
// candidates must include exactly those three Extensions roots for
// Chrome — proving Profile 10 (unreachable under the old hardcoded
// Default/Profile-1..9 list) is now discovered, and that no phantom
// Profile 2..9 candidates are produced for profiles that don't exist
// on disk.
func TestBrowserExtensionCandidateRootsEnumeratesChromiumProfiles(t *testing.T) {
	var chromeBase string
	switch runtime.GOOS {
	case "darwin":
		chromeBase = filepath.Join("Library", "Application Support", "Google", "Chrome")
	case "linux":
		chromeBase = filepath.Join(".config", "google-chrome")
	default:
		t.Skipf("Chromium candidate roots are only defined for darwin/linux, got %s", runtime.GOOS)
	}

	home := t.TempDir()
	full := filepath.Join(home, chromeBase)
	for _, prof := range []string{"Default", "Profile 1", "Profile 10"} {
		mustMkdir(t, filepath.Join(full, prof))
		mustWrite(t, filepath.Join(full, prof, "Preferences"), "{}")
	}

	got := BrowserExtensionCandidateRoots(home)
	gotSet := make(map[string]bool, len(got))
	for _, p := range got {
		gotSet[p] = true
	}

	for _, prof := range []string{"Default", "Profile 1", "Profile 10"} {
		want := filepath.Join(full, prof, "Extensions")
		if !gotSet[want] {
			t.Errorf("BrowserExtensionCandidateRoots(%q) missing %q; got %v", home, want, got)
		}
	}
	for _, prof := range []string{"Profile 2", "Profile 3", "Profile 4", "Profile 5", "Profile 6", "Profile 7", "Profile 8", "Profile 9"} {
		phantom := filepath.Join(full, prof, "Extensions")
		if gotSet[phantom] {
			t.Errorf("BrowserExtensionCandidateRoots(%q) contains phantom candidate %q for a profile that does not exist on disk",
				home, phantom)
		}
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

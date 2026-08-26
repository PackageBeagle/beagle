package agentcfg

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func scanDev(s *Scanner, p string) error { return s.ScanDevcontainer(p, model.Record{}) }

func TestScanDevcontainerAllLifecycleKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proj", ".devcontainer", "devcontainer.json")
	got := collect(t, path, `{
      "initializeCommand":"echo init",
      "onCreateCommand":"echo oncreate",
      "updateContentCommand":"echo update",
      "postCreateCommand":"echo postcreate",
      "postStartCommand":"echo poststart",
      "postAttachCommand":"echo postattach"}`, scanDev)

	if len(got) != 6 {
		t.Fatalf("got %d records, want 6", len(got))
	}
	for _, r := range got {
		if r.SourceType != ConfigTypeDevcontainerCmd {
			t.Errorf("SourceType = %q, want %q", r.SourceType, ConfigTypeDevcontainerCmd)
		}
		if r.PackageManager != AgentDevcontainer {
			t.Errorf("PackageManager = %q, want %q", r.PackageManager, AgentDevcontainer)
		}
	}
}

// The devcontainer spec allows string, array, and object forms for every
// lifecycle key.
func TestScanDevcontainerValueForms(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".devcontainer", "devcontainer.json")
		got := collect(t, path, `{"postCreateCommand":"npm install"}`, scanDev)
		if len(got) != 1 {
			t.Fatalf("got %d records, want 1", len(got))
		}
		if got[0].PackageName != "postCreateCommand" {
			t.Errorf("PackageName = %q, want postCreateCommand", got[0].PackageName)
		}
	})
	t.Run("array", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".devcontainer", "devcontainer.json")
		got := collect(t, path, `{"postCreateCommand":["npm","install"]}`, scanDev)
		if len(got) != 1 {
			t.Fatalf("got %d records, want 1", len(got))
		}
		if !strings.Contains(got[0].Extras[ExtraRiskSignals], "npm install") {
			t.Errorf("argv form not joined: %q", got[0].Extras[ExtraRiskSignals])
		}
	})
	t.Run("object", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".devcontainer", "devcontainer.json")
		got := collect(t, path, `{"postCreateCommand":{"deps":"npm ci","fmt":"prettier -w ."}}`, scanDev)
		if len(got) != 2 {
			t.Fatalf("got %d records, want 2 (one per named entry)", len(got))
		}
		names := map[string]bool{got[0].PackageName: true, got[1].PackageName: true}
		for _, want := range []string{"postCreateCommand:deps", "postCreateCommand:fmt"} {
			if !names[want] {
				t.Errorf("missing record named %q; got %v", want, names)
			}
		}
	})
}

func TestIsDevcontainerFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/proj/.devcontainer/devcontainer.json", true},
		{"/proj/.devcontainer.json", true},
		{"/proj/.devcontainer/sub/devcontainer.json", true},
		{"/proj/config/devcontainer.json", false},
	}
	for _, c := range cases {
		if got := IsDevcontainerFile(c.path); got != c.want {
			t.Errorf("IsDevcontainerFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

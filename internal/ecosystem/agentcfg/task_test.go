package agentcfg

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func scanTasks(s *Scanner, p string) error { return s.ScanTasks(p, model.Record{}) }

// runOn is nested under runOptions. Only folderOpen tasks are auto-run.
func TestScanTasksOnlyFolderOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proj", ".vscode", "tasks.json")
	got := collect(t, path, `{"version":"2.0.0","tasks":[
      {"label":"auto","command":"npm","args":["install"],"runOptions":{"runOn":"folderOpen"}},
      {"label":"manual","command":"make","runOptions":{"runOn":"default"}},
      {"label":"no runOptions","command":"ls"}]}`, scanTasks)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PackageName != "auto" {
		t.Errorf("PackageName = %q, want auto", got[0].PackageName)
	}
	if !strings.Contains(got[0].Extras[ExtraRiskSignals], "npm install") {
		t.Errorf("command not assembled from command+args: %q", got[0].Extras[ExtraRiskSignals])
	}
}

// Presentation suppression is the in-the-wild tell: the payload runs
// with nothing visible on screen.
func TestScanTasksPresentationSuppressed(t *testing.T) {
	cases := []struct {
		name         string
		presentation string
		want         bool
	}{
		{"silent reveal", `"presentation":{"reveal":"silent"},`, true},
		{"echo off", `"presentation":{"echo":false},`, true},
		{"focus off", `"presentation":{"focus":false},`, true},
		{"close on", `"presentation":{"close":true},`, true},
		{"visible", `"presentation":{"reveal":"always"},`, false},
		{"absent", ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".vscode", "tasks.json")
			got := collect(t, path, `{"tasks":[{"label":"t","command":"sh",`+c.presentation+
				`"runOptions":{"runOn":"folderOpen"}}]}`, scanTasks)
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1", len(got))
			}
			want := `"presentation_suppressed":false`
			if c.want {
				want = `"presentation_suppressed":true`
			}
			if !strings.Contains(got[0].Extras[ExtraRiskSignals], want) {
				t.Errorf("risk_signals = %q, want %s", got[0].Extras[ExtraRiskSignals], want)
			}
		})
	}
}

func TestScanTasksNPMScriptForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vscode", "tasks.json")
	got := collect(t, path, `{"tasks":[{"type":"npm","script":"dev",
      "runOptions":{"runOn":"folderOpen"}}]}`, scanTasks)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PackageName != "dev" {
		t.Errorf("PackageName = %q, want dev (label falls back to script)", got[0].PackageName)
	}
}

func TestIsTasksFile(t *testing.T) {
	if !IsTasksFile("/proj/.vscode/tasks.json") {
		t.Error("IsTasksFile should accept .vscode/tasks.json")
	}
	if IsTasksFile("/proj/build/tasks.json") {
		t.Error("IsTasksFile should reject tasks.json outside .vscode")
	}
}

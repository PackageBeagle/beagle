package agentcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

// collect runs a scanner over one written file and returns the records.
func collect(t *testing.T, path, content string, scan func(*Scanner, string) error) []model.Record {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, p, msg string) {},
	}
	if err := scan(s, path); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return got
}

func scanHooks(s *Scanner, p string) error { return s.ScanHooks(p, model.Record{}) }

// The nested shape is Claude Code settings.json and Codex hooks.json:
// each event maps to matcher groups, each carrying its own handler array.
func TestScanHooksNestedShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".codex", "hooks.json")
	got := collect(t, path, `{"hooks":{"SessionStart":[{"matcher":"startup",
      "hooks":[{"type":"command","command":"echo hi","timeout":600}]}]}}`, scanHooks)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	r := got[0]
	if r.PackageName != "SessionStart:startup" {
		t.Errorf("PackageName = %q, want SessionStart:startup", r.PackageName)
	}
	if r.PackageManager != AgentCodex {
		t.Errorf("PackageManager = %q, want %q", r.PackageManager, AgentCodex)
	}
	if r.SourceType != ConfigTypeHook {
		t.Errorf("SourceType = %q, want %q", r.SourceType, ConfigTypeHook)
	}
	if !strings.Contains(r.Extras[ExtraRiskSignals], "echo hi") {
		t.Errorf("risk_signals lost the command: %q", r.Extras[ExtraRiskSignals])
	}
	if !strings.Contains(r.Extras[ExtraRiskSignals], `"agent_shape":"nested"`) {
		t.Errorf("risk_signals = %q, want agent_shape nested", r.Extras[ExtraRiskSignals])
	}
}

// The flat shape is Cursor: command sits on the event's array element.
func TestScanHooksFlatShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cursor", "hooks.json")
	got := collect(t, path, `{"version":1,"hooks":{"beforeShellExecution":[
      {"command":".cursor/hooks/approve.sh","failClosed":true,"timeout":10}]}}`, scanHooks)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PackageName != "beforeShellExecution:*" {
		t.Errorf("PackageName = %q, want beforeShellExecution:*", got[0].PackageName)
	}
	if got[0].PackageManager != AgentCursor {
		t.Errorf("PackageManager = %q, want %q", got[0].PackageManager, AgentCursor)
	}
	if !strings.Contains(got[0].Extras[ExtraRiskSignals], `"agent_shape":"flat"`) {
		t.Errorf("risk_signals = %q, want agent_shape flat", got[0].Extras[ExtraRiskSignals])
	}
}

// Cursor documents matcher as an object while its examples show a
// string. Both must parse without dropping the row.
func TestScanHooksCursorMatcherBothForms(t *testing.T) {
	for name, matcher := range map[string]string{
		"string": `"matcher":"curl|wget",`,
		"object": `"matcher":{"tool":"Bash"},`,
		"absent": ``,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".cursor", "hooks.json")
			got := collect(t, path, `{"hooks":{"afterFileEdit":[{`+matcher+
				`"command":"fmt.sh"}]}}`, scanHooks)
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1", len(got))
			}
		})
	}
}

// This is the regression test for the dedupe collision: two handlers
// under one event+matcher must produce two distinct records. The two
// commands match no risk pattern, so the captured command text is the
// only thing separating them — which is what makes this a real guard.
// Commands that differ in their matched patterns would stay distinct
// even if the command itself were dropped from the record.
func TestScanHooksMultipleHandlersProduceDistinctRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	got := collect(t, path, `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[
      {"type":"command","command":"echo one"},
      {"type":"command","command":"echo two"}]}]}}`, scanHooks)

	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].StableID() == got[1].StableID() {
		t.Fatal("both handlers produced the same StableID; the second would be deduped away")
	}
}

func TestScanHooksSkipsNonCommandHandlers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	got := collect(t, path, `{"hooks":{"Stop":[{"matcher":"*","hooks":[
      {"type":"prompt","prompt":"summarize"}]}]}}`, scanHooks)
	if len(got) != 0 {
		t.Fatalf("got %d records, want 0 (prompt handlers do not execute commands)", len(got))
	}
}

func TestScanHooksRedactsCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	secret := "ghp_" + strings.Repeat("a", 36)
	got := collect(t, path, `{"hooks":{"Stop":[{"matcher":"*","hooks":[
      {"type":"command","command":"curl -H \"Authorization: `+secret+`\" https://x.example"}]}]}}`, scanHooks)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if strings.Contains(got[0].Extras[ExtraRiskSignals], secret) {
		t.Fatalf("hook command leaked a credential: %q", got[0].Extras[ExtraRiskSignals])
	}
}

func TestIsHookFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/u/.claude/hooks.json", true},
		{"/home/u/.codex/hooks.json", true},
		{"/home/u/.cursor/hooks.json", true},
		{"/home/u/.claude/plugins/cache/mp/p/1.0.0/hooks/hooks.json", true},
		{"/srv/app/config/hooks.json", false},
		{"/home/u/.claude/settings.json", false},
	}
	for _, c := range cases {
		if got := IsHookFile(c.path); got != c.want {
			t.Errorf("IsHookFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

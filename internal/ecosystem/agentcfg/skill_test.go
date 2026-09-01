package agentcfg

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func scanSkill(s *Scanner, p string) error { return s.ScanSkill(p, model.Record{}) }

func TestScanSkillDynamicContextAndGrants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proj", ".claude", "skills", "release", "SKILL.md")
	got := collect(t, path, "---\nname: release\nallowed-tools: Bash(git tag *) Bash(npm run *)\n---\n\n"+
		"Run this first:\n\n!`gh auth token`\n\nThen tag.\n", scanSkill)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	r := got[0]
	if r.PackageName != "release" {
		t.Errorf("PackageName = %q, want release", r.PackageName)
	}
	if r.Extras[ExtraHasDynamicContext] != "1" {
		t.Error("has_dynamic_context = 0, want 1")
	}
	if r.Extras[ExtraHasToolGrants] != "1" {
		t.Error("has_tool_grants = 0, want 1")
	}
	if r.Extras[ExtraHasCredentialAccess] != "1" {
		t.Error("has_credential_access = 0, want 1 (gh auth token)")
	}
	if !strings.Contains(r.Extras[ExtraRiskSignals], "Bash(git tag *)") {
		t.Errorf("grants missing from risk_signals: %q", r.Extras[ExtraRiskSignals])
	}
}

// allowed-tools is a space-separated scalar in normal use, but YAML
// permits a sequence. Both normalize to the same grants list.
func TestScanSkillGrantsBothYAMLForms(t *testing.T) {
	for name, frontmatter := range map[string]string{
		"scalar":   "allowed-tools: Bash(ls) Read(*)\n",
		"sequence": "allowed-tools:\n  - Bash(ls)\n  - Read(*)\n",
		"flow":     "allowed-tools: [Bash(ls), Read(*)]\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".claude", "skills", "x", "SKILL.md")
			got := collect(t, path, "---\nname: x\n"+frontmatter+"---\nbody\n", scanSkill)
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1", len(got))
			}
			rs := got[0].Extras[ExtraRiskSignals]
			if !strings.Contains(rs, "Bash(ls)") || !strings.Contains(rs, "Read(*)") {
				t.Errorf("grants = %q, want both patterns", rs)
			}
		})
	}
}

// Dynamic context injection is line-oriented. A backtick-bang inside
// prose or a fenced code block is not a DCI directive.
func TestScanSkillDynamicContextIsLineAnchored(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"own line", "!`gh auth token`\n", "1"},
		{"indented", "   !`whoami`\n", "1"},
		{"mid sentence", "Type !`foo` to run it.\n", "0"},
		{"in prose", "The !`x` syntax is explained here.\n", "0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".claude", "skills", "s", "SKILL.md")
			got := collect(t, path, "---\nname: s\n---\n"+c.body, scanSkill)
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1", len(got))
			}
			if got[0].Extras[ExtraHasDynamicContext] != c.want {
				t.Errorf("has_dynamic_context = %q, want %q", got[0].Extras[ExtraHasDynamicContext], c.want)
			}
		})
	}
}

func TestScanSkillNameFallsBackToDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "skills", "my-skill", "SKILL.md")
	got := collect(t, path, "---\ndescription: no name key\n---\nbody\n", scanSkill)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PackageName != "my-skill" {
		t.Errorf("PackageName = %q, want my-skill", got[0].PackageName)
	}
}

func TestScanSkillPluginScope(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "plugins", "cache", "mp", "p", "1.0.0", "skills", "s", "SKILL.md")
	got := collect(t, path, "---\nname: s\n---\nbody\n", scanSkill)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].InstallScope != ScopePlugin {
		t.Errorf("InstallScope = %q, want %q", got[0].InstallScope, ScopePlugin)
	}
}

func TestIsSkillFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/h/.claude/skills/x/SKILL.md", true},
		{"/h/.claude/plugins/cache/m/p/1/skills/x/SKILL.md", true},
		{"/srv/docs/SKILL.md", false},
		{"/h/.claude/skills/SKILL.md", false},
	}
	for _, c := range cases {
		if got := IsSkillFile(c.path); got != c.want {
			t.Errorf("IsSkillFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

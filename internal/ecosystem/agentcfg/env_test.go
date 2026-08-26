package agentcfg

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func scanSettings(s *Scanner, p string) error { return s.ScanSettings(p, model.Record{}) }

func TestScanSettingsEmitsHooksAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proj", ".claude", "settings.json")
	got := collect(t, path, `{
      "env": {"PATH": "./bin:/usr/bin", "EDITOR": "vim"},
      "hooks": {"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"echo hi"}]}]}
    }`, scanSettings)

	var hooks, envs int
	for _, r := range got {
		switch r.SourceType {
		case ConfigTypeHook:
			hooks++
		case ConfigTypeEnv:
			envs++
		}
	}
	if hooks != 1 {
		t.Errorf("got %d hook records, want 1", hooks)
	}
	if envs != 2 {
		t.Errorf("got %d env records, want 2", envs)
	}
}

func TestScanSettingsPathSignals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proj", ".claude", "settings.json")
	got := collect(t, path, `{"env":{"PATH":"./bin:/usr/bin:/bin"}}`, scanSettings)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	rs := got[0].Extras[ExtraRiskSignals]
	for _, want := range []string{`"overrides_path":true`, `"prepends_relative":true`, `"dangerous_var":true`} {
		if !strings.Contains(rs, want) {
			t.Errorf("risk_signals = %q, want %s", rs, want)
		}
	}
	if !strings.Contains(rs, "./bin:/usr/bin:/bin") {
		t.Errorf("PATH value should survive redaction intact: %q", rs)
	}
}

func TestScanSettingsDangerousVars(t *testing.T) {
	for _, name := range []string{"BASH_ENV", "NODE_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".claude", "settings.json")
			got := collect(t, path, `{"env":{"`+name+`":"/tmp/x"}}`, scanSettings)
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1", len(got))
			}
			if !strings.Contains(got[0].Extras[ExtraRiskSignals], `"dangerous_var":true`) {
				t.Errorf("%s not flagged dangerous: %q", name, got[0].Extras[ExtraRiskSignals])
			}
		})
	}
}

func TestScanSettingsRedactsSecretEnvValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	secret := "sk-ant-api03-" + strings.Repeat("z", 40)
	got := collect(t, path, `{"env":{"ANTHROPIC_API_KEY":"`+secret+`"}}`, scanSettings)

	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if strings.Contains(got[0].Extras[ExtraRiskSignals], secret) {
		t.Fatalf("env value leaked a credential: %q", got[0].Extras[ExtraRiskSignals])
	}
}

func TestScanSettingsEnterpriseScope(t *testing.T) {
	// The enterprise paths are absolute and fixed, so scope is asserted
	// through scopeForPath directly rather than by writing to /etc.
	scope, _ := scopeForPath("/etc/claude-code/managed-settings.json")
	if scope != ScopeEnterprise {
		t.Errorf("scope = %q, want %q", scope, ScopeEnterprise)
	}
	scope, _ = scopeForPath("/Library/Application Support/ClaudeCode/managed-settings.json")
	if scope != ScopeEnterprise {
		t.Errorf("scope = %q, want %q", scope, ScopeEnterprise)
	}
}

func TestIsSettingsFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/h/.claude/settings.json", true},
		{"/h/.claude/settings.local.json", true},
		{"/etc/claude-code/managed-settings.json", true},
		{"/Library/Application Support/ClaudeCode/managed-settings.json", true},
		{"/h/.gemini/settings.json", false},
		{"/h/.vscode/settings.json", false},
		{"/srv/app/settings.json", false},
	}
	for _, c := range cases {
		if got := IsSettingsFile(c.path); got != c.want {
			t.Errorf("IsSettingsFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

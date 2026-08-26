package agentcfg

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
	"github.com/packagebeagle/beagle/internal/model"
)

// dangerousVars are environment variable names that redirect execution:
// they change which binary runs, which interpreter startup code loads,
// or which shared library is injected. A project-scoped override of any
// of them is a code-execution path.
var dangerousVars = map[string]bool{
	"PATH": true, "BASH_ENV": true, "ENV": true, "NODE_OPTIONS": true,
	"PYTHONPATH": true, "PYTHONSTARTUP": true, "SITECUSTOMIZE": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true,
	"DYLD_FRAMEWORK_PATH": true, "PERL5OPT": true, "RUBYOPT": true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true,
}

// IsSettingsFile reports whether path is a Claude Code settings file.
// Dispatch is path-aware because "settings.json" is an ambiguous
// basename: mcp.IsGeminiSettingsJSON already claims it under .gemini,
// and VS Code uses it under .vscode.
func IsSettingsFile(path string) bool {
	switch filepath.Base(path) {
	case "settings.json", "settings.local.json":
		return filepath.Base(filepath.Dir(path)) == ".claude"
	case "managed-settings.json":
		return true
	}
	return false
}

// ScanSettings parses a Claude Code settings file, emitting hook records
// from the "hooks" key and env records from the "env" key. Both live in
// one file, so one read serves both.
func (s *Scanner) ScanSettings(path string, base model.Record) error {
	data, err := fsread.Bounded(path, s.MaxFileSize, s.Diag)
	if err != nil {
		return err
	}
	var doc struct {
		Env   map[string]string         `json:"env"`
		Hooks map[string][]matcherGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		s.diag("warn", path, "parse agent settings: "+err.Error())
		return nil
	}
	scope, projectPath := scopeForPath(path)

	events := make([]string, 0, len(doc.Hooks))
	for event := range doc.Hooks {
		events = append(events, event)
	}
	sort.Strings(events)
	for _, event := range events {
		for _, group := range doc.Hooks[event] {
			s.emitGroup(event, group, AgentClaudeCode, scope, projectPath, path, base)
		}
	}

	names := make([]string, 0, len(doc.Env))
	for name := range doc.Env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s.emitEnv(name, doc.Env[name], scope, projectPath, path, base)
	}
	return nil
}

// emitEnv emits one record for a configured environment variable.
func (s *Scanner) emitEnv(name, value, scope, projectPath, path string, base model.Record) {
	var sig Signals
	sig.ScanContent(value)
	sig.Set("value", Redact(name, value))
	sig.Set("overrides_path", name == "PATH")
	sig.Set("prepends_relative", name == "PATH" && hasRelativeComponent(value))
	sig.Set("dangerous_var", dangerousVars[strings.ToUpper(name)])
	s.emit(base, name, ConfigTypeEnv, AgentClaudeCode, scope, projectPath, path, sig)
}

// hasRelativeComponent reports whether a PATH-style value contains an
// entry resolved relative to the working directory. A relative entry
// means the binary that runs depends on where the agent was started,
// which is the whole point of the attack.
func hasRelativeComponent(value string) bool {
	for _, entry := range strings.Split(value, ":") {
		switch {
		case entry == "", entry == ".", entry == "..":
			return true
		case strings.HasPrefix(entry, "./"), strings.HasPrefix(entry, "../"):
			return true
		}
	}
	return false
}

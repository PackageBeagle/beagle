package agentcfg

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
	"github.com/packagebeagle/beagle/internal/model"
)

const Ecosystem = model.EcosystemAgentConfig

// config_type values, emitted in Record.SourceType.
const (
	ConfigTypeSkill           = "skill"
	ConfigTypeHook            = "hook"
	ConfigTypeEnv             = "env"
	ConfigTypeTaskAutorun     = "task_autorun"
	ConfigTypeDevcontainerCmd = "devcontainer_cmd"
)

// scope values, emitted in Record.InstallScope.
const (
	ScopeUser       = "user"
	ScopeProject    = "project"
	ScopePlugin     = "plugin"
	ScopeEnterprise = "enterprise"
)

// agent values, emitted in Record.PackageManager.
const (
	AgentClaudeCode   = "claude-code"
	AgentCodex        = "codex"
	AgentCursor       = "cursor"
	AgentVSCode       = "vscode"
	AgentDevcontainer = "devcontainer"
)

// Scanner reads agent-config files and emits one record per discovered
// configuration entry. Its methods are called from walk goroutines and
// hold no shared mutable state; Emit and Diag are synchronized by the
// caller.
type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsHookFile reports whether path is a lifecycle-hook file belonging to a
// known agent. Dispatch is path-aware rather than basename-only:
// "hooks.json" is a plausible filename elsewhere, and a row we cannot
// attribute to an agent is worse than no row. Requiring a .claude,
// .codex, or .cursor ancestor also picks up plugin-bundled
// hooks/hooks.json for free.
func IsHookFile(path string) bool {
	if filepath.Base(path) != "hooks.json" {
		return false
	}
	return agentFromPath(path) != ""
}

// agentFromPath infers the owning agent from the nearest recognized
// ancestor directory, or "" when there is none.
func agentFromPath(path string) string {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		switch seg {
		case ".claude":
			return AgentClaudeCode
		case ".codex":
			return AgentCodex
		case ".cursor":
			return AgentCursor
		}
	}
	return ""
}

// handler is one hook command. Both wire shapes decode into this.
type handler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// matcherGroup is the nested shape's per-event element (Claude Code
// settings.json, Codex hooks.json). Cursor's flat shape decodes into the
// same struct with Hooks empty and Command set, so one decode pass
// handles both and the shape is inferred from which field is populated.
type matcherGroup struct {
	Matcher json.RawMessage `json:"matcher"`
	Hooks   []handler       `json:"hooks"`
	Type    string          `json:"type"`
	Command string          `json:"command"`
}

// ScanHooks parses a hooks file and emits one record per command
// handler. Both the nested shape (Claude Code, Codex) and the flat shape
// (Cursor) are accepted; see D9 in the design record.
func (s *Scanner) ScanHooks(path string, base model.Record) error {
	data, err := fsread.Bounded(path, s.MaxFileSize, s.Diag)
	if err != nil {
		return err
	}
	var doc struct {
		Hooks map[string][]matcherGroup `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		s.diag("warn", path, "parse hooks: "+err.Error())
		return nil
	}
	if len(doc.Hooks) == 0 {
		s.diag("info", path, "no hooks parsed")
		return nil
	}
	agent := agentFromPath(path)
	if agent == "" {
		s.diag("debug", path, "hooks file not attributable to a known agent")
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
			s.emitGroup(event, group, agent, scope, projectPath, path, base)
		}
	}
	return nil
}

// emitGroup emits one record per command handler in a matcher group,
// handling both wire shapes.
func (s *Scanner) emitGroup(
	event string, group matcherGroup, agent, scope, projectPath, path string, base model.Record,
) {
	matcher := decodeMatcher(group.Matcher)
	if len(group.Hooks) == 0 {
		// Flat shape: the command sits on the group itself.
		if group.Command != "" && commandTyped(group.Type) {
			s.emitHook(event, matcher, group.Command, "flat", agent, scope, projectPath, path, base)
		}
		return
	}
	for _, h := range group.Hooks {
		if !commandTyped(h.Type) || h.Command == "" {
			s.diag("debug", path, "skipping non-command hook handler type "+h.Type)
			continue
		}
		s.emitHook(event, matcher, h.Command, "nested", agent, scope, projectPath, path, base)
	}
}

// commandTyped reports whether a handler runs a shell command. An empty
// type defaults to "command" in every agent's schema.
func commandTyped(t string) bool { return t == "" || t == "command" }

// decodeMatcher renders a matcher value as a display string. Cursor
// documents it as an object while its examples show a string, so both
// are accepted; anything else renders as "*".
func decodeMatcher(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "*"
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil && str != "" {
		return str
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj) > 0 {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+valueString(obj[k]))
		}
		return strings.Join(parts, ",")
	}
	return "*"
}

func valueString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func (s *Scanner) emitHook(
	event, matcher, command, shape, agent, scope, projectPath, path string, base model.Record,
) {
	redacted := RedactCommand(command)
	var sig Signals
	sig.ScanContent(command)
	sig.Set("event", event)
	sig.Set("matcher", matcher)
	sig.Set("command", redacted)
	sig.Set("agent_shape", shape)

	name := event + ":" + matcher
	s.emit(base, name, ConfigTypeHook, agent, scope, projectPath, path, sig)
}

// emit fills the shared record fields and hands the record to Emit.
func (s *Scanner) emit(
	base model.Record, name, configType, agent, scope, projectPath, path string, sig Signals,
) {
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = strings.ToLower(name)
	r.PackageManager = agent
	r.SourceType = configType
	r.SourceFile = path
	r.ProjectPath = projectPath
	r.InstallScope = scope
	r.Confidence = "medium"
	r.Extras = sig.Extras()
	s.Emit(r)
}

func (s *Scanner) diag(level, path, msg string) {
	if s.Diag != nil {
		s.Diag(level, path, msg)
	}
}

// scopeForPath classifies a config file by where it lives and returns the
// scope plus the project directory (empty for non-project scopes).
//
// Enterprise paths are absolute and fixed. A plugin-cache ancestor means
// plugin scope. A config directory directly under the user's home is user
// scope. Everything else is treated as project scope, with the project
// directory being the parent of the agent config directory.
func scopeForPath(path string) (scope, projectPath string) {
	slash := filepath.ToSlash(path)
	switch {
	case strings.HasPrefix(slash, "/Library/Application Support/ClaudeCode/"),
		strings.HasPrefix(slash, "/Library/Application Support/Cursor/"),
		strings.HasPrefix(slash, "/etc/claude-code/"),
		strings.HasPrefix(slash, "/etc/cursor/"):
		return ScopeEnterprise, ""
	case strings.Contains(slash, "/plugins/cache/"):
		return ScopePlugin, ""
	}
	dir := configDir(slash)
	if dir == "" {
		return ScopeProject, filepath.Dir(filepath.Dir(path))
	}
	if home, err := osUserHomeDir(); err == nil && home != "" {
		if filepath.Dir(dir) == filepath.Clean(home) {
			return ScopeUser, ""
		}
	}
	return ScopeProject, filepath.Dir(dir)
}

// configDir returns the nearest ancestor that is a recognized agent
// config directory, or "" when there is none.
func configDir(slash string) string {
	parts := strings.Split(slash, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		switch parts[i] {
		case ".claude", ".codex", ".cursor", ".vscode", ".devcontainer":
			return filepath.FromSlash(strings.Join(parts[:i+1], "/"))
		}
	}
	return ""
}

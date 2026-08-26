package agentcfg

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
	"github.com/packagebeagle/beagle/internal/model"
)

// lifecycleKeys are the devcontainer.json keys that execute commands, in
// the order the spec runs them.
var lifecycleKeys = []string{
	"initializeCommand",
	"onCreateCommand",
	"updateContentCommand",
	"postCreateCommand",
	"postStartCommand",
	"postAttachCommand",
}

// IsDevcontainerFile reports whether path is a devcontainer config. Three
// locations are valid per the spec: the .devcontainer directory, a
// subdirectory of it, and a .devcontainer.json at the project root.
func IsDevcontainerFile(path string) bool {
	base := filepath.Base(path)
	if base == ".devcontainer.json" {
		return true
	}
	if base != "devcontainer.json" {
		return false
	}
	slash := filepath.ToSlash(filepath.Dir(path))
	for _, seg := range strings.Split(slash, "/") {
		if seg == ".devcontainer" {
			return true
		}
	}
	return false
}

// ScanDevcontainer emits one record per lifecycle command. Each key's
// value may be a string, an argv array, or an object mapping names to
// commands; the object form emits one row per named entry.
func (s *Scanner) ScanDevcontainer(path string, base model.Record) error {
	data, err := fsread.Bounded(path, s.MaxFileSize, s.Diag)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		s.diag("warn", path, "parse devcontainer.json: "+err.Error())
		return nil
	}
	scope, projectPath := scopeForPath(path)
	for _, key := range lifecycleKeys {
		raw, ok := doc[key]
		if !ok {
			continue
		}
		for _, c := range decodeCommands(raw) {
			name := key
			if c.name != "" {
				name = key + ":" + c.name
			}
			var sig Signals
			sig.ScanContent(c.command)
			sig.Set("command", RedactCommand(c.command))
			sig.Set("trigger", key)
			s.emit(base, name, ConfigTypeDevcontainerCmd, AgentDevcontainer, scope, projectPath, path, sig)
		}
	}
	return nil
}

// namedCommand is one lifecycle command; name is set only for the object
// form, where the spec allows several commands to run in parallel.
type namedCommand struct {
	name    string
	command string
}

// decodeCommands handles all three value forms the devcontainer spec
// permits for a lifecycle key.
func decodeCommands(raw json.RawMessage) []namedCommand {
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		if str == "" {
			return nil
		}
		return []namedCommand{{command: str}}
	}
	var argv []string
	if err := json.Unmarshal(raw, &argv); err == nil {
		if len(argv) == 0 {
			return nil
		}
		return []namedCommand{{command: strings.Join(argv, " ")}}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []namedCommand
	for _, name := range names {
		for _, c := range decodeCommands(obj[name]) {
			out = append(out, namedCommand{name: name, command: c.command})
		}
	}
	return out
}

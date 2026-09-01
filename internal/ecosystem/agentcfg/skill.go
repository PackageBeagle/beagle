package agentcfg

import (
	"path/filepath"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
	"github.com/packagebeagle/beagle/internal/model"
)

// skillMaxBytes caps SKILL.md reads below the scanner's general
// MaxFileSize. At the 5 MiB default, a reference endpoint's ~120 plugin
// skills is 600 MB of worst-case scanning, and the content is
// attacker-plantable, so that worst case is reachable on purpose. Real
// SKILL.md files are tens of KB.
const skillMaxBytes = 1 << 20

// IsSkillFile reports whether path is a SKILL.md inside a skills
// directory: .../skills/<name>/SKILL.md. The <name> level is required so
// a stray SKILL.md directly under skills/ does not produce a row.
func IsSkillFile(path string) bool {
	if filepath.Base(path) != "SKILL.md" {
		return false
	}
	parent := filepath.Dir(path)
	return filepath.Base(filepath.Dir(parent)) == "skills"
}

// ScanSkill parses one SKILL.md: YAML frontmatter for the skill's name
// and declared tool grants, then the markdown body for dynamic-context
// commands and risk patterns.
func (s *Scanner) ScanSkill(path string, base model.Record) error {
	max := s.MaxFileSize
	if max <= 0 || max > skillMaxBytes {
		max = skillMaxBytes
	}
	data, err := fsread.Bounded(path, max, s.Diag)
	if err != nil {
		return err
	}
	frontmatter, body := splitFrontmatter(string(data))

	name := frontmatterValue(frontmatter, "name")
	if name == "" {
		name = filepath.Base(filepath.Dir(path))
	}
	grants := parseGrants(frontmatter)

	var sig Signals
	sig.HasToolGrants = len(grants) > 0
	if len(grants) > 0 {
		sig.Set("grants", grants)
	}
	commands := dynamicCommands(body)
	if len(commands) > 0 {
		sig.HasDynamicContext = true
		redacted := make([]string, 0, len(commands))
		for _, c := range commands {
			redacted = append(redacted, RedactCommand(c))
		}
		sig.Set("dynamic_commands", redacted)
	}
	sig.ScanContent(body)

	scope, projectPath := scopeForPath(path)
	s.emit(base, name, ConfigTypeSkill, AgentClaudeCode, scope, projectPath, path, sig)
	return nil
}

// splitFrontmatter separates YAML frontmatter from the markdown body. A
// document without a leading "---" fence has no frontmatter and is all
// body.
func splitFrontmatter(doc string) (frontmatter, body string) {
	trimmed := strings.TrimLeft(doc, "\ufeff \t\r\n")
	if !strings.HasPrefix(trimmed, "---") {
		return "", doc
	}
	rest := trimmed[3:]
	rest = strings.TrimPrefix(rest, "\r")
	rest = strings.TrimPrefix(rest, "\n")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return "", doc
	}
	after := rest[end+4:]
	return rest[:end], after
}

// frontmatterValue returns the scalar value for a top-level key, or ""
// when the key is absent or has a block value. This is a deliberately
// minimal YAML reader: the core module carries no YAML dependency, and
// only two keys are needed.
func frontmatterValue(frontmatter, key string) string {
	for _, line := range strings.Split(frontmatter, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(trimmed, key+":"))
	}
	return ""
}

// parseGrants reads allowed-tools in each of the three forms YAML
// permits for it: a space-separated scalar (the documented usage), a
// flow sequence, and a block sequence.
func parseGrants(frontmatter string) []string {
	lines := strings.Split(frontmatter, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "allowed-tools:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "allowed-tools:"))
		if strings.HasPrefix(value, "[") {
			return splitGrants(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
		}
		if value != "" {
			return splitGrants(value)
		}
		return blockSequence(lines[i+1:])
	}
	return nil
}

// splitGrants splits a tool-grant list on commas and whitespace that sit
// outside parentheses. Splitting on whitespace alone would shred a grant
// whose pattern spells out an argument — "Bash(git tag *)" is one grant,
// not three — and the scalar and flow forms differ only in whether the
// separator is a space or a comma.
func splitGrants(value string) []string {
	var out []string
	depth := 0
	start := -1
	for i, r := range value {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && (r == ',' || r == ' ' || r == '\t') {
			if start >= 0 {
				out = appendGrant(out, value[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = appendGrant(out, value[start:])
	}
	return out
}

// appendGrant trims surrounding quotes off one grant and drops it when
// nothing is left.
func appendGrant(out []string, grant string) []string {
	if g := strings.Trim(strings.TrimSpace(grant), `"'`); g != "" {
		return append(out, g)
	}
	return out
}

// blockSequence collects "  - item" lines until the block ends.
func blockSequence(lines []string) []string {
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") {
			if trimmed == "" {
				continue
			}
			break
		}
		out = appendGrant(out, trimmed[2:])
	}
	return out
}

// dynamicCommands extracts dynamic-context-injection commands from a
// skill body. The syntax is a "!" immediately followed by a
// backtick-wrapped command, anchored to the start of a line (leading
// whitespace allowed). Anchoring rather than substring-searching for the
// bang-backtick pair keeps prose and fenced examples from firing the
// signal.
func dynamicCommands(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, "!`") {
			continue
		}
		rest := trimmed[2:]
		end := strings.Index(rest, "`")
		if end <= 0 {
			continue
		}
		out = append(out, rest[:end])
	}
	return out
}

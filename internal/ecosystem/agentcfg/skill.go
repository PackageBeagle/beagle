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
	base = withFileIdentity(base, path, data)
	frontmatter, body := splitFrontmatter(string(data))

	name := frontmatterValue(frontmatter, "name")
	if name == "" {
		name = filepath.Base(filepath.Dir(path))
	}
	grants := parseGrants(frontmatter)

	var sig Signals
	tools := toolScope(frontmatter, grants)
	sig.HasUnrestrictedTools = tools != ScopeScoped
	sig.Set("tool_scope", tools)
	if len(grants) > 0 {
		sig.Set("grants", grants)
	}
	// The pattern lists are applied to the dynamic commands and nothing
	// else. Scanning the whole body matched prose and documentation —
	// "curl the endpoint" is a prompt, not a network call — which is what
	// made has_network_access fire on most skills. Capability comes
	// from the tool grants instead, and file identity from the digest.
	commands := dynamicCommands(body)
	if len(commands) > 0 {
		sig.HasDynamicContext = true
		redacted := make([]string, 0, len(commands))
		for _, c := range commands {
			redacted = append(redacted, RedactCommand(c))
			sig.ScanContent(c)
		}
		sig.Set("dynamic_commands", redacted)
	}

	scope, projectPath := scopeForPath(path)
	s.emit(base, name, ConfigTypeSkill, AgentClaudeCode, scope, projectPath, path, sig)
	return nil
}

// toolScope classifies a skill's declared capability.
//
// allowed-tools is documented as "Default: Inherits from conversation",
// so absence of the field is not absence of capability — it is
// unrestricted capability, and it is the majority case. A signal that
// fires on the skills which *declare* the field selects the constrained
// minority, which is backwards.
//
// A grant is unrestricted when it carries no "(...)" scope at all (bare
// Bash, Write, Edit) or when its scope is exactly "*". The second clause
// is not a detail: the one published malicious sample declares
// "allowed-tools: Bash(*)", and a rule keyed only on the presence of
// parentheses scores it as contained. A scope of "*" is the absence of a
// scope written out. "Bash(gh *)" is genuinely scoped and stays so — the
// test is on the whole scope being "*", not on containing one.
func toolScope(frontmatter string, grants []string) string {
	if !strings.Contains(frontmatter, "allowed-tools:") {
		return ScopeInherits
	}
	if len(grants) == 0 {
		// The key is present but empty, which grants nothing explicitly
		// and so still inherits.
		return ScopeInherits
	}
	for _, g := range grants {
		if isUnrestrictedGrant(g) {
			return ScopeUnrestrictedGrant
		}
	}
	return ScopeScoped
}

// isUnrestrictedGrant reports whether one allowed-tools entry places no
// limit on what it permits.
func isUnrestrictedGrant(grant string) bool {
	grant = strings.TrimSpace(grant)
	if grant == "" {
		return false
	}
	if grant == "*" {
		return true
	}
	open := strings.IndexByte(grant, '(')
	if open < 0 || !strings.HasSuffix(grant, ")") {
		// Bare Bash, Write, Edit — no scope to limit it.
		return true
	}
	return strings.TrimSpace(grant[open+1:len(grant)-1]) == "*"
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

// maxDynamicCommands bounds the commands recorded for one skill. The
// body is attacker-plantable, and a file of nothing but directives would
// otherwise put an unbounded list in the row. Both syntaxes count
// against it together.
const maxDynamicCommands = 16

// dynamicCommands extracts dynamic-context-injection commands from a
// skill body. Two syntaxes run before the body reaches the model, and
// both are collected:
//
//   - !`command` anywhere on a line, including mid-line, which is the
//     documented and prevailing form. Substitution is textual, so an
//     occurrence inside an ordinary code fence runs exactly the same and
//     is deliberately not suppressed.
//   - A ```! fence, every line of which is a command.
//
// An ordinary ```bash fence is what the model is *told* to run, which is
// a different claim from what the config *does* run, so its contents are
// not commands. An unterminated ```! fence runs to the end of the file;
// an unterminated inline opener is skipped. The syntax has no escape
// form, so none is handled.
//
// Substitution runs once over the original file and command output is
// not re-scanned, so a single pass is complete.
func dynamicCommands(body string) []string {
	var out []string
	inBangFence := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if inBangFence {
			if strings.HasPrefix(trimmed, "```") {
				inBangFence = false
				continue
			}
			if trimmed == "" {
				continue
			}
			if out = append(out, trimmed); len(out) >= maxDynamicCommands {
				return out
			}
			continue
		}
		if isBangFence(trimmed) {
			inBangFence = true
			continue
		}
		for _, cmd := range inlineDynamicCommands(line) {
			if out = append(out, cmd); len(out) >= maxDynamicCommands {
				return out
			}
		}
	}
	return out
}

// isBangFence reports whether a trimmed line opens a ```! fence.
func isBangFence(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "```") {
		return false
	}
	return strings.HasPrefix(strings.TrimLeft(trimmed, "`"), "!")
}

// inlineDynamicCommands returns every !`...` command on one line. An
// opener with no closing backtick ends the scan of that line: there is
// no command to record and nothing after it can be trusted to be one.
//
// The opening "!" must begin the line or follow whitespace. Every
// documented form does ("Files changed: !`git diff`", or the directive
// alone on its line), while a bang glued to the preceding character is
// part of a word or closes an inline-code span. Without the guard, a
// line of Excel error literals — `#REF!`, `#DIV/0!`, `#NUM!` — reads as
// six commands whose bodies are the prose between the backticks. That
// shape occurs in practice; it is not a constructed case.
func inlineDynamicCommands(line string) []string {
	var out []string
	for i := 0; i+1 < len(line); i++ {
		if line[i] != '!' || line[i+1] != '`' {
			continue
		}
		if i > 0 && line[i-1] != ' ' && line[i-1] != '\t' {
			continue
		}
		rest := line[i+2:]
		end := strings.IndexByte(rest, '`')
		if end < 0 {
			break
		}
		if end > 0 {
			out = append(out, rest[:end])
		}
		i += end + 2
	}
	return out
}

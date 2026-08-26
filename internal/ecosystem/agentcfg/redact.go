// Package agentcfg scans coding-agent configuration that creates
// code-execution paths on a developer machine: SKILL.md files, lifecycle
// hooks, agent environment overrides, IDE auto-run tasks, and
// devcontainer lifecycle commands.
//
// Unlike the other ecosystem scanners, this one records content — hook
// commands and environment values are the payload, and a table that
// reports a hook exists without reporting what it runs cannot support
// pattern-based detection. That is a deliberate carve-out from the
// never-capture-content posture documented on mcp.Scanner. The
// mitigation is that every captured string passes through Redact or
// RedactCommand first.
package agentcfg

import (
	"fmt"
	"math"
	"strings"
)

// secretNameFragments are matched case-insensitively as substrings of a
// variable name. A hit means the value is treated as secret regardless
// of its shape.
var secretNameFragments = []string{
	"key", "token", "secret", "password", "credential",
	"auth", "bearer", "private", "session", "cookie",
	"signature", "dsn",
}

// formatPrefix pairs a known credential prefix with the label reported
// in place of the value.
type formatPrefix struct {
	prefix string
	label  string
}

// Order matters: longer, more specific prefixes come before the shorter
// ones they extend, so "sk-ant-" wins over "sk-".
var secretFormats = []formatPrefix{
	{"sk-ant-", "anthropic-key"},
	{"sk-", "openai-key"},
	{"github_pat_", "github-pat"},
	{"ghp_", "github-pat"},
	{"gho_", "github-pat"},
	{"ghs_", "github-pat"},
	{"ghu_", "github-pat"},
	{"ghr_", "github-pat"},
	{"xoxb-", "slack-token"},
	{"xoxa-", "slack-token"},
	{"xoxp-", "slack-token"},
	{"xoxr-", "slack-token"},
	{"xoxs-", "slack-token"},
	{"AKIA", "aws-access-key"},
	{"ASIA", "aws-access-key"},
	{"AIza", "google-api-key"},
	{"glpat-", "gitlab-pat"},
	{"npm_", "npm-token"},
	{"dop_v1_", "digitalocean-token"},
	{"-----BEGIN", "pem"},
}

// Redact returns value unchanged when nothing marks it as secret, or a
// shape descriptor when it does. The descriptor keeps the row useful for
// detection — "this variable holds a GitHub PAT of length 40" — without
// the secret itself. name may be empty when the value has no associated
// variable name.
func Redact(name, value string) string {
	if value == "" {
		return value
	}
	if label := secretLabel(name, value); label != "" {
		return fmt.Sprintf("%s(%d)", label, len(value))
	}
	return value
}

// secretLabel returns the redaction label for value, or "" when the
// value is not secret-looking. The three triggers are checked in
// increasing order of cost.
func secretLabel(name, value string) string {
	if name != "" {
		lower := strings.ToLower(name)
		for _, frag := range secretNameFragments {
			if strings.Contains(lower, frag) {
				return "redacted:name"
			}
		}
	}
	if label := formatLabel(value); label != "" {
		return label
	}
	if looksHighEntropy(value) {
		return "redacted:entropy"
	}
	return ""
}

// formatLabel matches value against known credential formats. Prefix
// matches are case-sensitive because the formats themselves are; the
// all-hex check is not a prefix match and is applied last.
func formatLabel(value string) string {
	for _, f := range secretFormats {
		if strings.HasPrefix(value, f.prefix) {
			return "redacted:format:" + f.label
		}
	}
	if isJWT(value) {
		return "redacted:format:jwt"
	}
	if len(value) >= 32 && isAllHex(value) {
		return "redacted:format:hex"
	}
	return ""
}

// isJWT reports whether value has the three-segment shape of a JSON Web
// Token. Only the "eyJ" header prefix and the segment count are checked;
// decoding is unnecessary to decide the value should not be recorded.
func isJWT(value string) bool {
	return strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2
}

func isAllHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// looksHighEntropy is the fail-safe behind the name and format triggers,
// which are both denylists and fail open on a bespoke secret in a
// blandly named variable. Path-shaped values are exempted so PATH,
// PYTHONPATH, and LD_LIBRARY_PATH survive intact — those are the values
// an analyst most needs to read.
func looksHighEntropy(value string) bool {
	if len(value) < 20 || isPathShaped(value) {
		return false
	}
	return shannonEntropy(value) >= 3.5
}

// isPathShaped reports whether value looks like a filesystem path or a
// path list: it contains a separator and every slash-separated segment
// is drawn from the ordinary path alphabet. A token that merely contains
// a slash fails this test, since base64 alphabets include "+" and "=".
func isPathShaped(value string) bool {
	if !strings.ContainsAny(value, "/:") {
		return false
	}
	for _, seg := range strings.Split(strings.ReplaceAll(value, ":", "/"), "/") {
		for _, r := range seg {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			case r == '.', r == '_', r == '-', r == ' ':
			default:
				return false
			}
		}
	}
	return true
}

// shannonEntropy returns the per-character Shannon entropy of s in bits.
// Bytes are counted rather than runes: credential alphabets are ASCII,
// and byte counting avoids decoding cost on long values.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// RedactCommand redacts secret-looking tokens inside a command string
// while leaving the rest legible, so a rule can still match on the
// command's shape. Tokens are split on whitespace and on the quote and
// delimiter characters that commonly abut a credential in a shell
// command.
func RedactCommand(cmd string) string {
	if cmd == "" {
		return cmd
	}
	fields := strings.FieldsFunc(cmd, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '"', '\'', '=', ',', ';':
			return true
		}
		return false
	})
	out := cmd
	for _, tok := range fields {
		if label := formatLabel(tok); label != "" {
			out = strings.ReplaceAll(out, tok, fmt.Sprintf("%s(%d)", label, len(tok)))
			continue
		}
		if looksHighEntropy(tok) {
			out = strings.ReplaceAll(out, tok, fmt.Sprintf("redacted:entropy(%d)", len(tok)))
		}
	}
	return out
}

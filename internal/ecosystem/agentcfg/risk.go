package agentcfg

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Extras keys carried on agent-config records. The four booleans are
// derivable from ExtraRiskSignals; they are computed once in Signals and
// marshaled into both so they cannot drift.
const (
	ExtraHasDynamicContext    = "has_dynamic_context"
	ExtraHasUnrestrictedTools = "has_unrestricted_tools"
	ExtraHasNetworkAccess     = "has_network_access"
	ExtraHasCredentialAccess  = "has_credential_access"
	ExtraRiskSignals          = "risk_signals"
)

// tool_scope values, recording why has_unrestricted_tools reads as it
// does. A skill declaring no allowed-tools inherits the conversation's
// tools, which is the majority case and the reason the signal is phrased
// as "unrestricted" rather than "grants".
const (
	ScopeInherits          = "inherits"
	ScopeUnrestrictedGrant = "unrestricted_grant"
	ScopeScoped            = "scoped"
)

// networkPatterns and credentialPatterns are matched as case-insensitive
// literal substrings against a lowercased copy of the content. They are
// deliberately not regular expressions: the content is attacker-plantable,
// so a regex engine is a ReDoS surface in a tool whose job is reading
// hostile files, and literal matching does not backtrack.
//
// Only command- and path-shaped literals belong here. The bare
// dictionary words the first version carried matched prose, not
// behaviour, and did so on most files scanned: `nc ` inside `async`,
// `sync` and `func`, `fetch` inside prose and the `WebFetch` tool name,
// `token` inside `max_tokens` and `merchant_token`, `.env` inside
// `os.environ`.
//
// The trailing space in "curl " is doing two jobs: it drops `curly`, and
// it keeps the wrapper clients (`grpcurl`, `sc-curl`, `pay_curl`, any
// future `*-curl`) matching as substrings without enumerating them.
// Those are real network clients. Do not anchor these to a word
// boundary.
//
// Two gaps are accepted: a bare `grpcurl` at end of line with no
// arguments matches nothing, and `nc` with no trailing space is
// unreachable. Both trade recall on argument-less invocations for the
// removal of the dictionary-word noise.
var networkPatterns = []string{
	"curl ", "curl -", "wget ", "ncat ", "netcat ", "http://",
	"https://", "ftp://", "ssh://", "scp ", "sftp ", "rsync ",
	"aws s3", "gcloud ", "az storage", "urllib.request",
	"requests.get", "requests.post", "http.client",
}

var credentialPatterns = []string{
	"gh auth token", "git credential", ".ssh/", ".aws/",
	".gnupg/", ".kube/", ".docker/config", ".npmrc", ".pypirc",
	"security find-", "login.keychain", "printenv",
	"/etc/shadow", "cat .env", "cat ~/.env", "private_key",
	"aws_secret_access_key", "authorization: bearer",
}

// Signals holds the risk assessment for one agent-config row. Detail
// becomes the risk_signals JSON blob, whose shape varies by config_type.
type Signals struct {
	HasDynamicContext    bool
	HasUnrestrictedTools bool
	HasNetworkAccess     bool
	HasCredentialAccess  bool
	Detail               map[string]any
}

// Bounds on recorded match evidence. The content is attacker-plantable,
// so both the entry count and the window are fixed rather than
// proportional to the input.
//
// maxMatchEntries applies per list rather than to the two together: a
// file with eight network matches would otherwise hide its credential
// matches, and the credential half is the more useful one.
const (
	maxMatchEntries   = 8
	matchContextBytes = 80
)

// Match is one pattern hit with enough surrounding bytes to judge it. A
// responder reading `credential_patterns: ["token"]` could not tell
// `gh auth token` from `max_tokens`; that discrimination is the whole
// point of the row, so the evidence carries the literal, where it sat,
// and what it sat in.
//
// Offset is a byte offset into the scanned content — one hook command,
// or one skill dynamic command — not into the file.
type Match struct {
	Pattern string `json:"pattern"`
	Offset  int    `json:"offset"`
	Context string `json:"context"`
}

// ScanContent matches content against the network and credential pattern
// lists, setting the corresponding booleans and recording the evidence.
// It may be called more than once on one Signals value (each of a
// skill's dynamic commands, say); results accumulate.
func (s *Signals) ScanContent(content string) {
	if content == "" {
		return
	}
	lower := strings.ToLower(content)
	for _, p := range networkPatterns {
		if i := strings.Index(lower, p); i >= 0 {
			s.HasNetworkAccess = true
			s.appendMatch("network_matches", p, i, content)
		}
	}
	for _, p := range credentialPatterns {
		if i := strings.Index(lower, p); i >= 0 {
			s.HasCredentialAccess = true
			s.appendMatch("credential_matches", p, i, content)
		}
	}
}

// appendMatch records the first hit for one pattern, up to the per-list
// cap. Only the first is kept: a command that curls three endpoints is
// one behaviour, and repeating the literal adds bytes without adding
// discrimination.
func (s *Signals) appendMatch(key, pattern string, offset int, content string) {
	if s.Detail == nil {
		s.Detail = map[string]any{}
	}
	existing, _ := s.Detail[key].([]Match)
	if len(existing) >= maxMatchEntries {
		return
	}
	for _, m := range existing {
		if m.Pattern == pattern {
			return
		}
	}
	s.Detail[key] = append(existing, Match{
		Pattern: pattern,
		Offset:  offset,
		Context: matchContext(content, offset, len(pattern)),
	})
}

// matchContext returns up to matchContextBytes of content centred on the
// match, trimmed to rune boundaries so the JSON blob stays valid UTF-8,
// and redacted: the window is content capture, and every captured string
// in this package passes through the redactor first.
func matchContext(content string, offset, length int) string {
	pad := (matchContextBytes - length) / 2
	if pad < 0 {
		pad = 0
	}
	start := offset - pad
	if start < 0 {
		start = 0
	}
	end := start + matchContextBytes
	if end > len(content) {
		end = len(content)
	}
	for start < end && !utf8.RuneStart(content[start]) {
		start++
	}
	window := content[start:end]
	for len(window) > 0 && !utf8.ValidString(window) {
		window = window[:len(window)-1]
	}
	return RedactCommand(window)
}

// Set records a config-type-specific signal in the risk_signals blob.
func (s *Signals) Set(key string, value any) {
	if s.Detail == nil {
		s.Detail = map[string]any{}
	}
	s.Detail[key] = value
}

// Extras returns the five well-known extras keys for an agent-config
// record. encoding/json sorts map keys, so the risk_signals string is
// deterministic across runs — which matters because it feeds the
// record's StableID.
func (s Signals) Extras() map[string]string {
	detail := s.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	blob := "{}"
	if b, err := json.Marshal(detail); err == nil {
		blob = string(b)
	}
	return map[string]string{
		ExtraHasDynamicContext:    boolExtra(s.HasDynamicContext),
		ExtraHasUnrestrictedTools: boolExtra(s.HasUnrestrictedTools),
		ExtraHasNetworkAccess:     boolExtra(s.HasNetworkAccess),
		ExtraHasCredentialAccess:  boolExtra(s.HasCredentialAccess),
		ExtraRiskSignals:          blob,
	}
}

func boolExtra(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

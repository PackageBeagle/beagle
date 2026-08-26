package agentcfg

import (
	"encoding/json"
	"strings"
)

// Extras keys carried on agent-config records. The four booleans are
// derivable from ExtraRiskSignals; they are computed once in Signals and
// marshaled into both so they cannot drift.
const (
	ExtraHasDynamicContext   = "has_dynamic_context"
	ExtraHasToolGrants       = "has_tool_grants"
	ExtraHasNetworkAccess    = "has_network_access"
	ExtraHasCredentialAccess = "has_credential_access"
	ExtraRiskSignals         = "risk_signals"
)

// networkPatterns and credentialPatterns are matched as case-insensitive
// literal substrings against a lowercased copy of the content. They are
// deliberately not regular expressions: the content is attacker-plantable,
// so a regex engine is a ReDoS surface in a tool whose job is reading
// hostile files, and literal matching does not backtrack.
var networkPatterns = []string{
	"curl", "wget", "nc ", "ncat", "netcat", "fetch", "http://", "https://",
	"ftp://", "ssh://", "scp ", "sftp", "rsync", "aws s3", "gcloud", "az storage",
}

var credentialPatterns = []string{
	"gh auth token", "git credential", ".env", ".ssh/", ".aws/", ".gnupg/",
	".kube/", ".docker/config", ".npmrc", ".pypirc", "keychain", "security find-",
	"printenv", "/etc/shadow", "credentials", "secret", "api_key", "token",
	"password", "private_key",
}

// Signals holds the risk assessment for one agent-config row. Detail
// becomes the risk_signals JSON blob, whose shape varies by config_type.
type Signals struct {
	HasDynamicContext   bool
	HasToolGrants       bool
	HasNetworkAccess    bool
	HasCredentialAccess bool
	Detail              map[string]any
}

// ScanContent matches content against the network and credential pattern
// lists, setting the corresponding booleans and recording which patterns
// matched. It may be called more than once on one Signals value (a skill
// body and its frontmatter, say); results accumulate.
func (s *Signals) ScanContent(content string) {
	if content == "" {
		return
	}
	lower := strings.ToLower(content)
	for _, p := range networkPatterns {
		if strings.Contains(lower, p) {
			s.HasNetworkAccess = true
			s.appendDetail("urls", p)
		}
	}
	for _, p := range credentialPatterns {
		if strings.Contains(lower, p) {
			s.HasCredentialAccess = true
			s.appendDetail("credential_patterns", p)
		}
	}
}

// appendDetail appends value to the string slice at key, creating it as
// needed and skipping duplicates so repeated scans stay idempotent.
func (s *Signals) appendDetail(key, value string) {
	if s.Detail == nil {
		s.Detail = map[string]any{}
	}
	existing, _ := s.Detail[key].([]string)
	for _, v := range existing {
		if v == value {
			return
		}
	}
	s.Detail[key] = append(existing, value)
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
		ExtraHasDynamicContext:   boolExtra(s.HasDynamicContext),
		ExtraHasToolGrants:       boolExtra(s.HasToolGrants),
		ExtraHasNetworkAccess:    boolExtra(s.HasNetworkAccess),
		ExtraHasCredentialAccess: boolExtra(s.HasCredentialAccess),
		ExtraRiskSignals:         blob,
	}
}

func boolExtra(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

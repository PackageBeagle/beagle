package browserext

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/packagebeagle/beagle/internal/model"
)

func TestIsSafariExtensionManifest(t *testing.T) {
	const appex = "/Applications/Clipper.app/Contents/PlugIns/Clipper Extension.appex"
	cases := []struct {
		path string
		ok   bool
	}{
		{appex + "/Contents/Resources/manifest.json", true},
		{"/Users/u/Applications/X.app/Contents/PlugIns/Y.appex/Contents/Resources/manifest.json", true},
		{appex + "/Contents/Resources/sub/manifest.json", false},
		{appex + "/Contents/Resources/package.json", false},
		{"/Applications/Clipper.app/Contents/PlugIns/Clipper Extension/Contents/Resources/manifest.json", false},
		{"/Applications/Clipper/Contents/PlugIns/X.appex/Contents/Resources/manifest.json", false},
		{"/Applications/Clipper.app/Contents/Extensions/X.appex/Contents/Resources/manifest.json", false},
		{"/Applications/Clipper.app/Contents/Resources/manifest.json", false},
	}
	for _, c := range cases {
		ok, appexDir, appDir := IsSafariExtensionManifest(c.path)
		if ok != c.ok {
			t.Errorf("IsSafariExtensionManifest(%q) = %v, want %v", c.path, ok, c.ok)
		}
		if c.path == appex+"/Contents/Resources/manifest.json" &&
			(appexDir != appex || appDir != "/Applications/Clipper.app") {
			t.Errorf("dirs = %q, %q", appexDir, appDir)
		}
	}
}

func TestPlistStrings(t *testing.T) {
	data := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.Clipper.Extension</string>
	<key>CFBundleVersion</key>
	<integer>12</integer>
	<key>CFBundleSupportedPlatforms</key>
	<array><string>MacOSX</string><dict><key>InArray</key><string>x</string></dict></array>
	<key>NSExtension</key>
	<dict>
		<key>NSExtensionAttributes</key>
		<dict><key>Deep</key><string>a &amp; b</string></dict>
		<key>NSExtensionPointIdentifier</key>
		<string>com.apple.Safari.web-extension</string>
	</dict>
	<key>After</key>
	<string>top</string>
</dict>
</plist>`
	got, err := plistStrings([]byte(data))
	if err != nil {
		t.Fatalf("plistStrings: %v", err)
	}
	want := map[string]string{
		"CFBundleIdentifier":                     "com.example.Clipper.Extension",
		"NSExtension.NSExtensionAttributes.Deep": "a & b",
		"NSExtension.NSExtensionPointIdentifier": "com.apple.Safari.web-extension",
		"After":                                  "top",
	}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}

	if _, err := plistStrings([]byte("bplist00\x01\x02")); !errors.Is(err, errBinaryPlist) {
		t.Errorf("binary plist err = %v, want errBinaryPlist", err)
	}
	if _, err := plistStrings([]byte("<plist><dict><key>a</key><string>b</dict>")); err == nil {
		t.Error("malformed plist: want error")
	}
}

// writeSafariAppex builds <dir>/Host.app/Contents/PlugIns/Ext.appex with
// the given Info.plist body and manifest, returning the manifest path.
func writeSafariAppex(t *testing.T, dir, infoPlist, manifest string) string {
	t.Helper()
	contents := filepath.Join(dir, "Host.app", "Contents", "PlugIns", "Ext.appex", "Contents")
	res := filepath.Join(contents, "Resources")
	if err := os.MkdirAll(filepath.Join(res, "_locales", "en"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(contents, "Info.plist"):                 infoPlist,
		filepath.Join(res, "manifest.json"):                   manifest,
		filepath.Join(res, "_locales", "en", "messages.json"): `{"extName":{"message":"Clipper"}}`,
	}
	for p, body := range files {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(res, "manifest.json")
}

func safariInfoPlist(bundleID, point, shortVersion string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
<key>CFBundleShortVersionString</key><string>` + shortVersion + `</string>
<key>NSExtension</key><dict>
<key>NSExtensionPointIdentifier</key><string>` + point + `</string>
</dict></dict></plist>`
}

func scanSafari(t *testing.T, manifestPath string) ([]model.Record, []string, error) {
	t.Helper()
	var out []model.Record
	var diags []string
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(level, path, msg string) { diags = append(diags, level+": "+msg) },
	}
	ok, appexDir, appDir := IsSafariExtensionManifest(manifestPath)
	if !ok {
		t.Fatalf("fixture path not recognized: %s", manifestPath)
	}
	err := s.ScanSafariExtension(manifestPath, appexDir, appDir, model.Record{})
	return out, diags, err
}

func TestScanSafariExtension(t *testing.T) {
	dir := t.TempDir()
	mp := writeSafariAppex(t, dir,
		safariInfoPlist("com.example.Clipper.Extension", safariExtensionPoint, "3.0.2"),
		`{"name":"__MSG_extName__","version":"2.1","default_locale":"en","manifest_version":3}`)
	out, _, err := scanSafari(t, mp)
	if err != nil {
		t.Fatalf("ScanSafariExtension: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1", len(out))
	}
	r := out[0]
	if r.PackageName != "Clipper" || r.NormalizedName != "com.example.clipper.extension" || r.Version != "2.1" {
		t.Errorf("name/id/version = %q/%q/%q", r.PackageName, r.NormalizedName, r.Version)
	}
	if r.PackageManager != "safari-extension" || r.SourceType != "browser-extension" ||
		r.RootKind != model.RootKindBrowserExtension || r.Confidence != "high" {
		t.Errorf("record = %+v", r)
	}
	if r.ProjectPath != filepath.Join(dir, "Host.app") || r.SourceFile != mp {
		t.Errorf("project/source = %q/%q", r.ProjectPath, r.SourceFile)
	}
}

func TestScanSafariExtensionVersionFallback(t *testing.T) {
	mp := writeSafariAppex(t, t.TempDir(),
		safariInfoPlist("com.example.Clipper.Extension", safariExtensionPoint, "3.0.2"),
		`{"name":"Plain"}`)
	out, _, err := scanSafari(t, mp)
	if err != nil || len(out) != 1 {
		t.Fatalf("records=%d err=%v", len(out), err)
	}
	if out[0].Version != "3.0.2" || out[0].PackageName != "Plain" {
		t.Errorf("version/name = %q/%q, want bundle version fallback", out[0].Version, out[0].PackageName)
	}
}

func TestScanSafariExtensionSkipsOtherExtensionPoints(t *testing.T) {
	mp := writeSafariAppex(t, t.TempDir(),
		safariInfoPlist("com.example.Widget", "com.apple.widgetkit-extension", "1.0"),
		`{"name":"x","version":"1"}`)
	out, diags, err := scanSafari(t, mp)
	if err != nil || len(out) != 0 || len(diags) != 0 {
		t.Errorf("records=%d diags=%v err=%v, want none", len(out), diags, err)
	}
}

func TestScanSafariExtensionBinaryPlistWarns(t *testing.T) {
	mp := writeSafariAppex(t, t.TempDir(), "bplist00\x00\x01", `{"name":"x","version":"1"}`)
	out, diags, err := scanSafari(t, mp)
	if err != nil || len(out) != 0 {
		t.Fatalf("records=%d err=%v, want no record and no error", len(out), err)
	}
	if len(diags) != 1 || !strings.HasPrefix(diags[0], "warn: ") || !strings.Contains(diags[0], "binary") {
		t.Errorf("diags = %v, want one binary-plist warning", diags)
	}
}

func TestScanSafariExtensionErrors(t *testing.T) {
	cases := map[string]struct{ plist, manifest string }{
		"no bundle id":    {safariInfoPlist("", safariExtensionPoint, "1"), `{"name":"x"}`},
		"bad manifest":    {safariInfoPlist("com.example.X", safariExtensionPoint, "1"), `{`},
		"malformed plist": {"<plist><dict><key>a</key>", `{"name":"x"}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			mp := writeSafariAppex(t, t.TempDir(), c.plist, c.manifest)
			out, _, err := scanSafari(t, mp)
			if err == nil || len(out) != 0 {
				t.Errorf("records=%d err=%v, want error and no record", len(out), err)
			}
		})
	}
}

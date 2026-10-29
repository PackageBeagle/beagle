package browserext

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
	"github.com/packagebeagle/beagle/internal/model"
)

// Safari web extensions are app extensions bundled inside a host app:
//
//	<host>.app/Contents/PlugIns/<name>.appex/Contents/Info.plist
//	<host>.app/Contents/PlugIns/<name>.appex/Contents/Resources/manifest.json
//
// manifest.json is a standard WebExtension manifest. Info.plist carries
// the bundle identifier and the extension point that marks the appex as
// a Safari web extension. Records report what is installed; whether a
// user has turned an extension on is per-user Safari state that is not
// read, the same as for Chromium and Firefox.

// safariExtensionPoint is NSExtensionPointIdentifier for a Safari web
// extension.
const safariExtensionPoint = "com.apple.Safari.web-extension"

var errBinaryPlist = errors.New("binary property list (only XML is supported)")

// IsSafariExtensionManifest reports whether path is the manifest.json of
// an app extension inside a host app, returning the .appex and host .app
// directories. Whether the appex is a Safari web extension is decided by
// its Info.plist when it is scanned.
func IsSafariExtensionManifest(path string) (ok bool, appexDir, appDir string) {
	if filepath.Base(path) != "manifest.json" {
		return false, "", ""
	}
	resources := filepath.Dir(path)
	contents := filepath.Dir(resources)
	appexDir = filepath.Dir(contents)
	plugins := filepath.Dir(appexDir)
	appContents := filepath.Dir(plugins)
	appDir = filepath.Dir(appContents)
	if filepath.Base(resources) != "Resources" ||
		filepath.Base(contents) != "Contents" ||
		filepath.Ext(appexDir) != ".appex" ||
		filepath.Base(plugins) != "PlugIns" ||
		filepath.Base(appContents) != "Contents" ||
		filepath.Ext(appDir) != ".app" {
		return false, "", ""
	}
	return true, appexDir, appDir
}

// ScanSafariExtension reads the appex's Info.plist and manifest.json and
// emits one record when the appex is a Safari web extension. An appex
// for any other extension point is skipped without a diagnostic.
func (s *Scanner) ScanSafariExtension(manifestPath, appexDir, appDir string, base model.Record) error {
	plistPath := filepath.Join(appexDir, "Contents", "Info.plist")
	data, err := fsread.Bounded(plistPath, s.MaxFileSize, s.Diag)
	if err != nil {
		return err
	}
	info, err := plistStrings(data)
	if errors.Is(err, errBinaryPlist) {
		if s.Diag != nil {
			s.Diag("warn", plistPath, "Safari extension not inventoried: "+err.Error())
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse %s: %w", plistPath, err)
	}
	if info["NSExtension.NSExtensionPointIdentifier"] != safariExtensionPoint {
		return nil
	}
	bundleID := strings.TrimSpace(info["CFBundleIdentifier"])
	if bundleID == "" {
		return fmt.Errorf("%s: Safari web extension has no CFBundleIdentifier", plistPath)
	}

	data, err = fsread.Bounded(manifestPath, s.MaxFileSize, s.Diag)
	if err != nil {
		return err
	}
	var m webExtManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse %s: %w", manifestPath, err)
	}
	name := s.extensionName(m, filepath.Dir(manifestPath))
	if name == "" {
		name = bundleID
	}
	// The manifest version is the extension's own; the bundle version
	// tracks the host app and is only a fallback.
	version := strings.TrimSpace(m.Version)
	if version == "" {
		version = strings.TrimSpace(info["CFBundleShortVersionString"])
	}
	confidence := "high"
	if version == "" || name == bundleID {
		confidence = "medium"
	}

	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = strings.ToLower(bundleID)
	r.Version = version
	r.ProjectPath = appDir
	r.PackageManager = "safari-extension"
	r.SourceType = "browser-extension"
	r.SourceFile = manifestPath
	r.RootKind = model.RootKindBrowserExtension
	r.Confidence = confidence
	s.Emit(r)
	return nil
}

// plistFrame is one open dict or array while decoding a property list.
type plistFrame struct {
	prefix string // key path of this dict, "" or ending in "."
	skip   bool   // inside an array: values have no key path
}

// plistStrings returns the string values of an XML property list's
// dictionaries, keyed by their key path ("NSExtension.NSExtensionPointIdentifier"
// for a nested dict). Values inside arrays and non-string values are
// omitted. Binary property lists are rejected with errBinaryPlist.
func plistStrings(data []byte) (map[string]string, error) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return nil, errBinaryPlist
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	out := map[string]string{}
	var stack []plistFrame
	key := ""
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "dict", "array":
				f := plistFrame{skip: t.Name.Local == "array"}
				if n := len(stack); n > 0 {
					f.skip = f.skip || stack[n-1].skip
					f.prefix = stack[n-1].prefix + key + "."
				}
				stack = append(stack, f)
			case "key", "string":
				var v string
				if err := dec.DecodeElement(&v, &t); err != nil {
					return nil, err
				}
				if t.Name.Local == "key" {
					key = v
				} else if n := len(stack); n > 0 && !stack[n-1].skip {
					out[stack[n-1].prefix+key] = v
				}
			}
		case xml.EndElement:
			if (t.Name.Local == "dict" || t.Name.Local == "array") && len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

package agentcfg

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// writeManifest creates dir/.claude-plugin/marketplace.json with body and
// returns dir.
func writeManifest(t *testing.T, dir, body string) string {
	t.Helper()
	manifest := filepath.Join(dir, ".claude-plugin")
	if err := os.MkdirAll(manifest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifest, "marketplace.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCatalogDirsListsDeclaredPluginDirs(t *testing.T) {
	root := writeManifest(t, t.TempDir(), `{
	  "name": "example",
	  "plugins": [
	    {"name": "one", "source": "./plugins/one"},
	    {"name": "two", "source": "./plugins/two"}
	  ]
	}`)
	got := CatalogDirs(root, 1<<20, nil)
	sort.Strings(got)
	want := []string{filepath.Join(root, "plugins", "one"), filepath.Join(root, "plugins", "two")}
	if len(got) != len(want) {
		t.Fatalf("CatalogDirs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("CatalogDirs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// A single-plugin marketplace names the repository root as its own
// source. Every installed plugin under ~/.claude/plugins/cache carries
// such a manifest, so pruning on it would drop the live plugin's skills
// and hooks from the inventory — the opposite of what the catalog
// exclusion is for.
func TestCatalogDirsIgnoresSelfReferentialSource(t *testing.T) {
	for _, src := range []string{"./", ".", "", "./."} {
		t.Run("source="+src, func(t *testing.T) {
			root := writeManifest(t, t.TempDir(), `{"plugins":[{"name":"self","source":"`+src+`"}]}`)
			if got := CatalogDirs(root, 1<<20, nil); len(got) != 0 {
				t.Errorf("CatalogDirs = %v, want none (root is not catalog content)", got)
			}
		})
	}
}

// A source is a path inside the repository. Anything that climbs out of
// it names a directory the manifest has no authority over.
func TestCatalogDirsRejectsEscapingSource(t *testing.T) {
	for _, src := range []string{"../sibling", "./plugins/../../escape", "/etc"} {
		t.Run("source="+src, func(t *testing.T) {
			root := writeManifest(t, t.TempDir(), `{"plugins":[{"name":"x","source":"`+src+`"}]}`)
			if got := CatalogDirs(root, 1<<20, nil); len(got) != 0 {
				t.Errorf("CatalogDirs = %v, want none", got)
			}
		})
	}
}

// Remote sources are objects, not strings. They name nothing on disk.
func TestCatalogDirsIgnoresNonStringSource(t *testing.T) {
	root := writeManifest(t, t.TempDir(), `{"plugins":[
	  {"name":"remote","source":{"source":"github","repo":"o/r"}},
	  {"name":"local","source":"./plugins/local"}
	]}`)
	got := CatalogDirs(root, 1<<20, nil)
	if len(got) != 1 || got[0] != filepath.Join(root, "plugins", "local") {
		t.Errorf("CatalogDirs = %v, want only the local source", got)
	}
}

func TestCatalogDirsNoManifest(t *testing.T) {
	var diags []string
	diag := func(level, path, msg string) { diags = append(diags, level+" "+path+" "+msg) }
	if got := CatalogDirs(t.TempDir(), 1<<20, diag); got != nil {
		t.Errorf("CatalogDirs = %v, want nil", got)
	}
	if len(diags) != 0 {
		t.Errorf("diagnostics = %v, want none for an ordinary directory", diags)
	}
}

// Failure mode matches the TOML parser's: an unparseable manifest prunes
// nothing and the catalog is inventoried as before — noisy, never
// silently absent — with a warn naming the file.
func TestCatalogDirsMalformedManifestPrunesNothing(t *testing.T) {
	root := writeManifest(t, t.TempDir(), `{"plugins": [ this is not json`)
	var diags []string
	diag := func(level, path, msg string) { diags = append(diags, level+"|"+path+"|"+msg) }
	if got := CatalogDirs(root, 1<<20, diag); got != nil {
		t.Errorf("CatalogDirs = %v, want nil", got)
	}
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %v, want exactly one", diags)
	}
	if !strings.HasPrefix(diags[0], "warn|") {
		t.Errorf("diagnostic = %q, want warn level", diags[0])
	}
	if !strings.Contains(diags[0], filepath.Join(root, ".claude-plugin", "marketplace.json")) {
		t.Errorf("diagnostic = %q, want the manifest path named", diags[0])
	}
}

func TestCatalogDirsManifestWithoutPlugins(t *testing.T) {
	root := writeManifest(t, t.TempDir(), `{"name":"empty"}`)
	if got := CatalogDirs(root, 1<<20, nil); got != nil {
		t.Errorf("CatalogDirs = %v, want nil", got)
	}
}

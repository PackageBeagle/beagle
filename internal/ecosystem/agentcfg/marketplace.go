package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/packagebeagle/beagle/internal/fsread"
)

// marketplaceManifest is the path, relative to a marketplace repository's
// root, of the manifest that makes it one.
var marketplaceManifest = filepath.Join(".claude-plugin", "marketplace.json")

// marketplaceMaxBytes caps manifest reads. A manifest listing several
// hundred plugins is still well under a megabyte.
const marketplaceMaxBytes = 1 << 20

// marketplaceDoc is the subset of marketplace.json that matters here.
// source is json.RawMessage because it is a string for a local plugin
// directory and an object for a remote one, and only the former names
// anything on disk.
type marketplaceDoc struct {
	Plugins []struct {
		Name   string          `json:"name"`
		Source json.RawMessage `json:"source"`
	} `json:"plugins"`
}

// CatalogDirs returns the absolute directories under dir that a plugin
// marketplace manifest declares as catalog content: published plugins
// that are browsable from this repository but are not installed and not
// loadable by any agent on the endpoint. The caller prunes them.
//
// It returns nil for an ordinary directory, which is the overwhelmingly
// common case, at the cost of one stat per directory walked.
//
// A manifest that cannot be read or parsed prunes nothing and earns a
// warn naming the file: the catalog is then inventoried as it was
// before, which is noisy but never silently absent.
func CatalogDirs(dir string, maxBytes int64, diag func(level, path, msg string)) []string {
	path := filepath.Join(dir, marketplaceManifest)
	if st, err := os.Lstat(path); err != nil || !st.Mode().IsRegular() {
		return nil
	}
	if maxBytes <= 0 || maxBytes > marketplaceMaxBytes {
		maxBytes = marketplaceMaxBytes
	}
	// The read is bounded and its own failures are already reported, so a
	// nil diag here would double-report; pass it through and return.
	data, err := fsread.Bounded(path, maxBytes, diag)
	if err != nil {
		return nil
	}
	var doc marketplaceDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		if diag != nil {
			diag("warn", path, "unparseable plugin marketplace manifest; catalog content is inventoried as ordinary config: "+err.Error())
		}
		return nil
	}
	var out []string
	for _, p := range doc.Plugins {
		var src string
		if json.Unmarshal(p.Source, &src) != nil {
			continue
		}
		if abs, ok := catalogDir(dir, src); ok {
			out = append(out, abs)
		}
	}
	return out
}

// catalogDir resolves one plugins[].source against the repository root,
// reporting the absolute directory to prune.
//
// A source naming the root itself is refused. Single-plugin marketplaces
// write "./" there, and every plugin installed under
// ~/.claude/plugins/cache carries its origin repository's manifest, so
// honouring it would prune the live plugin's skills and hooks — the
// inverse of what the exclusion is for. It is also why pruning is
// manifest-driven rather than a blanket subtree prune: the repository's
// own .claude/ is live config for anyone who opens it, and a marketplace
// repository is a high-value injection target precisely because it
// publishes to the fleet.
//
// A source that climbs out of the repository is refused for the same
// reason in reverse: the manifest has no authority over a directory it
// does not contain.
func catalogDir(root, source string) (string, bool) {
	source = strings.TrimSpace(source)
	if source == "" || filepath.IsAbs(source) {
		return "", false
	}
	abs := filepath.Join(root, source)
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", false
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return abs, true
}

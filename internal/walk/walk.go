// Package walk implements a bounded, safety-aware filesystem walker.
//
// The walker visits directories under configured roots, applying:
//   - exclude-directory matching by name
//   - symlink-loop protection via visited-inode tracking
//   - bounded recursion: it does not descend into node_modules subtrees
//     beyond what targeted scanners need (those scanners walk their own
//     bounded depth)
//
// File-size limits and per-file safety live in the scanners themselves.
package walk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/charlievieth/fastwalk"
)

// Default excludes target sensitive/credential dirs and high-cost caches that
// developer machines accumulate. The list is intentionally conservative.
//
// macOS-specific entries cover TCC-protected user trees that produce
// "operation not permitted" noise without yielding inventory, large media
// libraries that the OS itself walks lazily, and Apple intelligence /
// suggestion caches that frequently appear in permission-error reports.
// These apply even when an operator explicitly passes --root "$HOME";
// the excludes only narrow what is walked under each root.
var DefaultExcludes = []string{
	".git",
	".hg",
	".svn",
	".ssh",
	".gnupg",
	".aws",
	".azure",
	".config/gcloud",
	".kube",
	".docker",

	// macOS Library — caches, mail/messages, browser profiles, system
	// intelligence/suggestions, trial data, and weather caches. The
	// scanner does not need to read any of these and they routinely
	// produce TCC denials when scanned under a LaunchAgent.
	//
	// The curated default roots in cmd/beagle only include the
	// handful of Library subpaths the scanner actually wants (e.g.
	// Library/Python/<v>/site-packages via the Homebrew path, or
	// Library/Application Support/Claude for MCP configs). When an
	// operator explicitly passes --root "$HOME", these suffix-component
	// matches keep the walker out of every other Library subtree that
	// is either TCC-protected, OS-managed, or just irrelevant.
	"Library/Caches",
	"Library/Application Support/Google/Chrome",
	"Library/Application Support/Chromium",
	"Library/Application Support/Firefox",
	"Library/Application Support/BraveSoftware",
	"Library/Application Support/Microsoft Edge",
	"Library/Application Support/Vivaldi",
	"Library/Application Support/Arc",
	"Library/Safari",
	"Library/Containers",
	"Library/ContainerManager",
	"Library/Daemon Containers",
	"Library/Group Containers",
	"Library/Mail",
	"Library/Messages",
	"Library/Suggestions",
	"Library/Trial",
	"Library/Weather",
	"Library/Metadata",
	"Library/Biome",
	"Library/PersonalizationPortrait",
	"Library/CoreFollowUp",
	"Library/HomeKit",
	"Library/Mobile Documents",
	"Library/CloudStorage",
	"Library/com.apple.aiml.instrumentation",
	"Library/IdentityServices",
	"Library/Keychains",
	"Library/Cookies",
	"Library/HTTPStorages",
	"Library/WebKit",
	"Library/Autosave Information",
	"Library/Saved Application State",
	"Library/DoNotDisturb",
	"Library/DuetExpertCenter",
	"Library/IntelligencePlatform",
	"Library/Photos",
	"Library/Sharing",
	"Library/Shortcuts",
	"Library/StatusKit",
	"Library/Accounts",
	"Library/Assistant",
	"Library/CallServices",
	"Library/com.apple.icloud.searchpartyd",
	"Library/FaceTime",
	"Library/Family",
	"Library/FrontBoard",
	"Library/Reminders",
	"Library/Springboard",
	"Library/Sync Services",
	"Library/Voice Trigger",

	// macOS media libraries. These are large, OS-managed, and contain
	// nothing the package scanner can use.
	"Movies/TV",
	"Music/Music",
	"Pictures/Photos Library.photoslibrary",
	"Pictures/Photo Booth Library",

	// Generic caches and high-cost build/dependency cache trees.
	".cache",
	".npm/_cacache",
	".pnpm-store",
	".yarn/cache",
	".gradle",
	".m2",
	".ivy2",
	".sbt",
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	".tox",
	".venv-cache",
	".nox",
	".terraform",
	"node_modules/.cache",

	// Bazel: project-local and well-known user caches. The output_base
	// and disk_cache layouts hold many partial / synthesized fixture
	// METADATA files that look like Python dist-info but are not
	// installed packages.
	"bazel-cache",
	"bazel-out",
	"bazel-bin",
	"bazel-testlogs",
	".bazel-cache",
	".cache/bazel",

	// Editor remote-server runtime/state/log subtrees are excluded so the
	// per-user `extensions/` root remains scannable while server runtime
	// binaries, globalStorage tokens/blobs, logs, and caches are not walked.
	".vscode-server/data",
	".vscode-server/bin",
	".vscode-server/cli",
	".vscode-server/logs",
	".vscode-server-insiders/data",
	".vscode-server-insiders/bin",
	".vscode-server-insiders/cli",
	".vscode-server-insiders/logs",
	".cursor-server/data",
	".cursor-server/bin",
	".cursor-server/cli",
	".cursor-server/logs",
	".windsurf-server/data",
	".windsurf-server/bin",
	".windsurf-server/cli",
	".windsurf-server/logs",

	// Agent-plugin marketplace catalogs: local clones of browsable plugin
	// directories (Claude Code registers the official marketplace
	// automatically on first interactive start; Claude Desktop cowork
	// sessions and Codex stage similar bundles). Their .mcp.json files
	// and lockfiles are install templates, not configuration that runs
	// on the endpoint — on a reference machine they accounted for 87% of
	// MCP records and 10% of npm records. The installed set lives
	// elsewhere (e.g. ~/.claude/plugins/cache) and remains scanned.
	// Entries are anchored multi-component suffixes, never a bare
	// "marketplaces", so a user directory of that name is unaffected.
	".claude/plugins/marketplaces",
	"cowork_plugins/marketplaces",
	".codex/.tmp",
}

// Visitor is called for every directory entry the walker decides to surface.
// The walker itself does not open files; scanners decide what to read.
type Visitor func(path string, d fs.DirEntry) error

type Options struct {
	Roots    []string
	Excludes []string

	// OnError receives non-fatal errors; the walker continues afterward.
	OnError func(path string, err error)
}

// ErrSkip can be returned by a Visitor to skip a directory subtree.
var ErrSkip = filepath.SkipDir

// Walk traverses Roots, invoking visit on every entry. Excluded directories
// (matched by basename or by suffix path component) are skipped entirely.
func Walk(opts Options, visit Visitor) error {
	excludes := normalizeExcludes(opts.Excludes)
	seen := make(map[string]struct{})

	// BEAGLE_FASTWALK=1 selects the parallel fastwalk traversal. The
	// visitor and OnError callback are then invoked from multiple
	// goroutines and must be safe for concurrent use.
	parallel := os.Getenv("BEAGLE_FASTWALK") == "1"

	for _, root := range opts.Roots {
		root = filepath.Clean(root)
		var err error
		if parallel {
			err = walkOneParallel(root, excludes, seen, opts.OnError, visit)
		} else {
			err = walkOne(root, excludes, seen, opts.OnError, visit)
		}
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(root, err)
			}
		}
	}
	return nil
}

// walkOneParallel mirrors walkOne's skip/dedup semantics but drives the
// traversal with charlievieth/fastwalk, which reads directories from a
// pool of goroutines. The shared seen map is guarded by mu; the visitor
// must itself be concurrency-safe.
func walkOneParallel(root string, excludes excludeSet, seen map[string]struct{}, onErr func(string, error), visit Visitor) error {
	var mu sync.Mutex
	return fastwalk.Walk(&fastwalk.Config{}, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if onErr != nil {
				onErr(path, err)
			}
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if isExcluded(path, d.Name(), excludes) {
				return filepath.SkipDir
			}
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			if key, ok := dirKey(path); ok {
				mu.Lock()
				_, dup := seen[key]
				if !dup {
					seen[key] = struct{}{}
				}
				mu.Unlock()
				if dup {
					return filepath.SkipDir
				}
			}
		}
		if verr := visit(path, d); verr != nil {
			if errors.Is(verr, filepath.SkipDir) {
				return filepath.SkipDir
			}
			if onErr != nil {
				onErr(path, verr)
			}
		}
		return nil
	})
}

func walkOne(root string, excludes excludeSet, seen map[string]struct{}, onErr func(string, error), visit Visitor) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if onErr != nil {
				onErr(path, err)
			}
			// Skip unreadable directories outright, but continue elsewhere.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if isExcluded(path, d.Name(), excludes) {
				return filepath.SkipDir
			}
			// Directory symlinks are never descended into. filepath.WalkDir
			// does not follow them on its own, and we explicitly skip any
			// directory-shaped symlink we encounter so the walker never
			// crosses into an unrelated subtree by indirection. d.Type()
			// carries the mode bits from the readdir that discovered the
			// entry, so this costs no extra syscall.
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			// Symlink-loop guard via device+inode.
			if key, ok := dirKey(path); ok {
				if _, dup := seen[key]; dup {
					return filepath.SkipDir
				}
				seen[key] = struct{}{}
			}
		}
		if verr := visit(path, d); verr != nil {
			if errors.Is(verr, filepath.SkipDir) {
				return filepath.SkipDir
			}
			if onErr != nil {
				onErr(path, verr)
			}
		}
		return nil
	})
}

// excludeSet splits the configured excludes by shape so the hot path
// does no work proportional to the full exclude list. Single-component
// excludes are matched against the entry's basename through a map;
// multi-component ones are stored with the leading separator already
// attached so matching is one strings.HasSuffix with no allocation.
type excludeSet struct {
	bare   map[string]struct{}
	suffix []string
}

func normalizeExcludes(in []string) excludeSet {
	out := excludeSet{bare: make(map[string]struct{}, len(in))}
	seen := make(map[string]struct{}, len(in))
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		x = filepath.Clean(x)
		if _, dup := seen[x]; dup {
			continue
		}
		seen[x] = struct{}{}
		if strings.ContainsRune(x, filepath.Separator) {
			out.suffix = append(out.suffix, string(filepath.Separator)+x)
		} else {
			out.bare[x] = struct{}{}
		}
	}
	return out
}

// isExcluded reports whether a directory is excluded, either by its
// basename or by a trailing path-component sequence. fullPath is
// expected to be clean — every path WalkDir produces is.
func isExcluded(fullPath, base string, excludes excludeSet) bool {
	if _, ok := excludes.bare[base]; ok {
		return true
	}
	// Suffix-component match: an exclude like "Library/Caches" or
	// ".config/gcloud" matches any path ending in that sequence.
	for _, ex := range excludes.suffix {
		if strings.HasSuffix(fullPath, ex) {
			return true
		}
	}
	return false
}

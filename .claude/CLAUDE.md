# PackageBeagle — project context

Read-only endpoint inventory scanner for package/extension/dev-tool
metadata on macOS and Linux. Emits NDJSON; matches an optional exposure
catalog for supply-chain response. Binary: `beagle`. Also ships as an
osquery extension.

Design rationale and decision records live in
[`docs/DESIGN.md`](../docs/DESIGN.md) — read it before changing the
module layout, the osquery table, or the walker's exclude list.

## Origin & license

- Derived from [perplexityai/bumblebee](https://github.com/perplexityai/bumblebee)
  (Apache-2.0), substantially modified and renamed. Independent
  project, not a fork tracking upstream.
- Apache-2.0 obligations are met at the repo level: `LICENSE` kept,
  modified-file notice satisfied via `NOTICE` + the README's
  "Attribution" section (upstream shipped no per-file copyright headers
  or NOTICE, so there was nothing per-file to preserve).
- Not derived from upstream git history: fresh `git init`, tracked
  files only, then renamed. `main` has no common ancestor with upstream
  and the project does not track it.
- The upstream commit the tree was taken from, `d753592` (2026-06-25),
  is preserved as the tag `bumblebee-base` so `git diff bumblebee-base
  main` shows the modifications. The tag is the only upstream history
  in the repo — do not merge or rebase onto it. Most of that diff is
  the mechanical rename, not substantive change.

## Naming

- Brand/org **PackageBeagle**; module/binary **beagle**.
- Module path is `github.com/packagebeagle/beagle` (not
  `.../packagebeagle`) to avoid import stutter and keep a clean library
  import path.
- The rename touched three token forms: `bumblebee`→`beagle`,
  `Bumblebee`→`Beagle`, `BUMBLEBEE`→`BEAGLE`. Env vars are `BEAGLE_*`;
  `scanner_name` in emitted records is `"beagle"`.

## Conventions / invariants

- Core module: **zero non-stdlib dependencies**. Keep it that way; put
  any third-party deps in the `osquery/` nested module.
- `threat_intel/*.json` are **data** (real compromised-package
  coordinates and tool-reference prose). Do not token-rename or treat
  versions there as the tool's version.
- `cmd/beagle/version.go` and `osquery/version.go` each have a
  `fileDefault` that must be kept in sync with the `VERSION` file by
  hand (they do not read the file).
- One-shot scanner, not a daemon: each run scans once and exits;
  cadence is the runner's job.
- The `osquery/` extension is a nested Go module so osquery-go/Thrift
  stay out of the core. Local dev needs a gitignored root `go.work`
  (`go work init . ./osquery`) — never commit it.
- Do not promote packages out of `internal/` speculatively; see
  `docs/DESIGN.md`.
- Go toolchain split: core `go.mod` targets **1.25**, `osquery/go.mod`
  targets **1.26**. Any CI/release step that reads the osquery module
  (through `go.work`) must set up Go **1.26** — the release workflow's
  `go work init` fails on 1.25.
- Releasing: push a `vX.Y.Z` tag (drives `.goreleaser.yaml` → both
  `beagle` and `beagle.ext` tarballs). `v*` tags (and `bumblebee-base`)
  are **immutable** — the `protect-tags` ruleset blocks
  delete/update/force-push, so a botched release tag can't be reused:
  bump `VERSION` + both `fileDefault`s and tag the next patch instead.
- `main` is protected (PR-only). Branch before committing; never commit
  or push to `main` directly.

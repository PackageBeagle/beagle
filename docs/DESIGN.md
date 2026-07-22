# beagle — design record

Why the project is shaped the way it is, and the decisions a contributor
would otherwise have to reverse-engineer or re-litigate. Per-ecosystem
on-disk detail lives in [inventory-sources.md](inventory-sources.md);
record shapes live in [state-model.md](state-model.md) and
[schema/](schema/).

## Core invariants

**The core module has zero non-stdlib dependencies.** This is the
constraint everything else bends around. beagle reads
attacker-plantable files on endpoints during incident response; every
dependency is attack surface and a supply-chain link in a tool whose
job is auditing supply chains. Third-party dependencies go in the
nested `osquery/` module, never in the root module.

**One-shot, not a daemon.** Each run scans once and exits. Cadence is
the runner's job (launchd, systemd, osquery's schedule). The osquery
extension runs one scan, or serves a short-TTL cache, per `Generate`
call — it does not hold a resident scanner.

**Read-only.** beagle never writes to, modifies, or executes anything
it inventories.

**`threat_intel/*.json` is data, not code.** Those files hold real
compromised-package coordinates from public reporting. Version strings
in them are the compromised packages' versions and have nothing to do
with beagle's own version. Do not bulk-edit or rename tokens across
them.

**`VERSION` is hand-synced into two places.** `cmd/beagle/version.go`
and `osquery/version.go` each carry a `fileDefault` constant that must
match the `VERSION` file. Neither reads the file at build time (the
ldflags path is what release builds use; `fileDefault` is the
`go build` fallback). Bumping `VERSION` without touching both is the
easiest mistake to make in this repo.

## Module layout: the nested osquery module

osquery-go pulls in Apache Thrift, which would break the
zero-dependency invariant if it lived in the root module. So the
extension is a **separate Go module** at `osquery/`, with its own
`go.mod`.

It imports the core's `internal/` packages directly. This is legal:
Go's `internal/` visibility is a **path-prefix** rule, and
`github.com/packagebeagle/beagle/osquery` is under the
`github.com/packagebeagle/beagle` prefix. Verified empirically, not
assumed.

The result: the core module stays zero-dependency, and only the nested
module carries osquery-go, Thrift, and `golang.org/x/sync`.

Local development uses a **gitignored** root `go.work`:

```sh
go work init . ./osquery   # once per checkout
```

It is gitignored by design — do not commit it. Releases require the
core to be tagged so the nested `go.mod` can `require` a real version;
no `replace` directive is ever committed.

**No public library yet.** Promoting packages out of `internal/` is
deferred until there is a real external consumer. The osquery
extension is the first consumer and will teach us the right API
surface. Do not promote speculatively.

**The record seam.** `scanner.Run(ctx, cfg)` pushes records through a
concrete `*output.Emitter`. The extension collects rows via an
in-memory emitter and re-decodes the NDJSON the emitter just
serialized. That round-trip is a deliberate tradeoff: it keeps
`internal/` untouched. Extract an `Emitter` interface only when
there's a second reason to.

---

# osquery extension

`beagle.ext` exposes the inventory to osquery as a SQL table,
`beagle_packages`. Scan roots and depth (profile) are configurable per
query. Build and usage instructions are in
[`osquery/README.md`](../osquery/README.md); this section is the design
rationale.

The extension drives the existing `scanner.Run(ctx, cfg)` seam and
reuses `roots.Resolve`, `endpoint.Current`, `model`, and `output`
unchanged. It required no `internal/` changes.

```
osquery/
  go.mod              module github.com/packagebeagle/beagle/osquery
                      (requires github.com/osquery/osquery-go — the
                      osquery org module, not the older kolide fork)
  main.go             entrypoint: flags + register table plugin
  table/packages.go   table plugin: Columns() + Generate()
  scan.go             bridge: run scanner.Run, collect []model.Record
  cache.go            TTL cache + per-key singleflight
```

The binary is built as `beagle.ext` — osquery requires the `.ext`
suffix on extension executables.

## Table: `beagle_packages`

One table, one row per package/extension/dev-tool record, with 19
columns: a subset of `model.Record`'s fields plus the scope columns
(`profile`, `root`) and the `scan_truncated` status column, rather than
all of them (D5). osquery has no boolean type, so bools map to INTEGER;
everything else is TEXT.

Endpoint: `endpoint_username` only — it is the one `Record.Endpoint`
field that varies per row (under `BEAGLE_ALL_USERS`); the rest are
constant across an entire scan (D5).

Package fields: `ecosystem`, `package_name`, `normalized_name`,
`version`, `root_kind`, `install_scope`, `package_manager`,
`source_type`, `source_file`, `confidence`, `requested_spec`,
`server_name`, plus three typed specials:

| column | type | note |
|---|---|---|
| `direct_dependency` | INTEGER | null when unset — tri-state preserved |
| `has_lifecycle_scripts` | INTEGER | 0/1 |
| `lifecycle_scripts` | TEXT | JSON array |

Scope and status columns:

| column | role |
|---|---|
| `profile` | hidden + index: usable in `WHERE`, absent from `SELECT *` (D5). Equality constraint + output. Absent ⇒ `baseline`. Equals `Record.Profile`. |
| `root` | hidden + index: usable in `WHERE`, absent from `SELECT *` (D5). Equality constraint + output. Output is the enclosing configured root for that row, byte-for-byte as configured. |
| `scan_truncated` | 1 if the scan hit `MaxDuration` and returned partial results. |

Their cells stay in the row map even though the columns are hidden:
SQLite re-verifies `WHERE` predicates against returned rows, so a
predicate on `profile` or `root` needs a real value to check against,
not just an index hint.

An `ecosystem` EQUALS constraint is also pushed down before rows are
built (D6): non-matching records are dropped from the scan outcome
before serialization, the same treatment `root` already gets via
`roots.Resolve`.

Two details that are easy to get wrong:

**Null in an INTEGER column.** osquery-go rows are
`map[string]string` with no NULL type. "Null" is an empty-string cell,
which osquery core coerces to SQL NULL in an INTEGER column — `IS NULL`
matches. That is how `direct_dependency` keeps its tri-state.

**`root` output must not be normalized.** It is computed with the same
longest-enclosing-root logic `scanner.newRootKindLookup` uses for
`root_kind`, but returns the root path instead of its kind. Matching
uses cleaned paths internally, but the *emitted* value is the
configured root byte-for-byte — never `filepath.Clean`ed or `Abs`ed.
SQLite re-verifies WHERE predicates against returned rows, so if a
query says `root = '/path/'` with a trailing slash and you emit the
cleaned form, every row is silently dropped. A record whose source file
is outside every configured root gets an empty `root`.

## Query semantics

`Generate` reads `QueryContext` constraints and translates them into
`roots.Resolve(profile, explicitRoots, opts)` — the same function the
CLI uses — then into a `scanner.Config`.

**How constraints actually arrive** (verified, see below):

- SQLite decomposes `IN (...)` and OR'd equalities on virtual tables
  into **one `Generate` call per value**, each with a single equality
  constraint. `root IN ('/a','/b')` is two calls, two scans, two cache
  entries. The implementation handles 1..n values per call because it's
  cheap, but the semantics, caching, and scan-count expectations are
  per-call.
- `root = ''` is **not delivered at all** — the constraint list arrives
  empty. Conflicting equalities (`profile = 'p1' AND profile = 'p2'`)
  likewise. Both degenerate to an unconstrained default-profile scan
  whose rows SQLite then post-filters to zero. The extension cannot
  detect or reject these; they are known degenerations, equivalent in
  cost to an unconstrained query.

Translation rules:

- **`profile`**: an EQUALS constraint selects the profile; absent, the
  extension substitutes `baseline` before calling `roots.Resolve`
  (`Resolve("")` errors with "profile is required", so the default has
  to happen in the extension, as `normalizeProfile` does in the CLI). A
  non-EQUALS operator returns an error rather than silently scanning
  the wrong scope (D1). An unrecognized value returns the
  `roots.Resolve` error.
- **`root`**: EQUALS values become the `explicit` roots argument under
  the resolved profile. With no EQUALS constraint, the profile's
  curated default roots are used. Non-EQUALS operators (LIKE, GLOB,
  comparisons) do *not* affect scoping: default roots are scanned and
  SQLite post-filters the rows. That is intentional and useful —
  `WHERE root LIKE '/Users/%'` works as you'd expect.
- **Guardrails are inherited unchanged** from `roots.Resolve`: a broad
  home/filesystem root under `baseline`/`project` returns the "re-run
  with --profile deep" error; `deep` requires at least one explicit
  root; all-users cannot combine with explicit roots or `deep`.
- If `roots.Resolve` errors, `Generate` returns it and yields no rows.
  Interactive osqueryi shows it to the user; under osqueryd it lands in
  the daemon log. The second return value (notes) is forwarded to the
  extension's diagnostic log, as the CLI forwards it to diagnostics.

## Scan bridge (`scan.go`)

1. Build `BaseRecord` from `endpoint.Current(deviceID)`, a fresh
   16-byte hex run id, `model.SchemaVersion`, `model.ScannerName`, and
   `ScanTime` set to scan start in RFC3339Nano — the same full
   `model.Record` shape the CLI builds, even though `beagle_packages`
   only projects 19 of its fields (D5); the rest round-trip through the
   NDJSON decode step below unused by the table. `scanner_version`
   comes from the nested module (it cannot import `cmd/beagle`):
   injected via goreleaser `-X` ldflags with a `debug.ReadBuildInfo`
   fallback, mirroring the CLI's `currentVersion()` rather than adding
   a third hand-synced version constant.
2. Create `output.New(recordsBuf, diagWriter, runID)` with an
   in-memory buffer and a diag writer forwarding to the extension's
   stderr / osquery log.
3. Call `scanner.Run(ctx, cfg)` with `Catalog: nil`,
   `FindingsOnly: false`, `MaxDuration` per profile, and the resolved
   roots. **`MaxFileSize` must be set explicitly** to the CLI's 5 MiB
   default: `scanner.Run` has no default of its own and
   `fsread.Bounded` treats `<= 0` as *unbounded*, which is a memory
   hazard in a resident process reading attacker-plantable files.
4. Decode the buffer line by line into `[]model.Record` (guarding on
   `record_type == "package"`), returning them with the resolved
   `[]scanner.Root` (needed for the `root` output column) and the
   `Truncated` flag.

With no catalog, only package records are written and `Run` emits no
scan_summary, so the buffer holds package-record NDJSON only.

## Caching and bounds (`cache.go`)

- **TTL cache** keyed on `profile + "\x00" + roots sorted and joined
  with "\x00"` (NUL cannot appear in paths), memoizing decoded records,
  resolved roots, and the truncated flag for `BEAGLE_CACHE_TTL`
  (default 60s). Repeated queries and osquery health probes inside the
  window reuse the last scan instead of re-walking the filesystem.
- **`MaxDuration` defaults per profile** — baseline 30s, project 60s,
  deep 120s — so one scan cannot hang the daemon while a deep incident
  sweep still gets a budget it can realistically finish in. A single
  global 30s default would leave most deep queries truncated. Query
  authors choose the profile and therefore the budget; the semaphore
  bounds what that can occupy.
- **Truncated scans are returned but not cached**, each row carrying
  `scan_truncated = 1`, so the next query retries rather than serving
  partial-as-complete for the whole TTL (D2).
- **Per-key singleflight, not a global mutex** (D3). The lock covers
  only map access. Concurrent queries for the same key wait on and
  share one scan; different keys proceed independently. A global mutex
  held across a 30s scan would stall every other query on the
  extension.
- **A semaphore bounds total concurrent scans (2).** `root` is a
  query-controllable input: every distinct value is a cache miss that
  walks the filesystem with 4 walker goroutines, and `MaxDuration`
  bounds one scan, not N.

## Flags and configuration (`main.go`)

osquery controls the extension's argv. The watcher launches it with
exactly `--socket <path> --timeout 3 --interval 3`, plus `--verbose`
when osquery itself runs verbose. Two consequences:

- The extension **must** define `socket`, `timeout`, `interval`, and
  `verbose` flags. stdlib `flag` exits on unknown flags, so a missing
  `verbose` definition kills the extension at startup under a verbose
  osquery. osquery-go registers no flags itself; the extension parses
  them and passes the socket path to `NewExtensionManagerServer`.
- There is **no way to pass `--beagle_*` flags through osquery
  loading**, so beagle's knobs are environment variables (D4),
  consistent with the CLI's existing `BEAGLE_USERS_DIR`:

| env var | effect |
|---|---|
| `BEAGLE_CACHE_TTL` | default `60s`; global across profiles — TTL is cache policy, not scan policy |
| `BEAGLE_MAX_DURATION` | overrides the per-profile scan budget for every profile |
| `BEAGLE_ALL_USERS`, `BEAGLE_USERS_DIR` | map to `roots.Opts{AllUsers, UsersDirOverride}` |
| `BEAGLE_DEVICE_ID_ENV` | env var *name* whose value is resolved into the endpoint's device id internally, matching the CLI's `--device-id-env`. Never a literal value. `beagle_packages` has no device-id column (D5), so this currently has no visible effect on query results. |

Set these on the process that launches osqueryd (launchd plist,
systemd unit, MDM). A root-owned daemon's environment is not modifiable
or readable by non-admin users.

## Deployment: running as root

Under osqueryd (root), `HomesForExpansion` resolves to the process
owner's home, so a default `baseline` query covers `/var/root` plus the
system roots — **not user homes**. Covering user homes requires
`BEAGLE_ALL_USERS`, which is macOS-only (`roots` reports "not
supported" on Linux). This is a deployment surprise if undocumented;
see `osquery/README.md`.

## Verified osquery behavior

Everything below was confirmed empirically against osqueryd 5.23.1
using a throwaway extension that logged argv and every `Generate`
call, driven via osqueryi (a symlink to the osqueryd binary; shell mode
uses the same watcher and table machinery — the daemon-with-autoload
path was not separately exercised). These are osquery-core behaviors
unit tests cannot see, so re-verify them if you touch constraint
handling:

- `IN`/`OR` equalities: one `Generate` call per value, one equality
  constraint each. Never aggregated.
- `LIKE` on a column: delivered with operator 65. Ignorable, but then
  SQLite post-filters, silently returning zero rows if the emitted
  value cannot match.
- `root = ''` and conflicting equalities: not delivered at all; the
  call arrives unconstrained.
- Trailing-slash constraint vs cleaned output: SQLite re-verifies the
  predicate and drops rows whose emitted value differs byte-for-byte.
- Empty string in an INTEGER column: coerced to SQL NULL (`IS NULL`
  matches).
- `Generate` error: shown directly to the interactive osqueryi user;
  daemon log otherwise.
- Extension argv: `--socket`, `--timeout`, `--interval`, plus
  `--verbose` when osquery runs verbose. Nothing else.

## Decisions

- **D1 — non-EQUALS operators on `profile` return an error.** LIKE on a
  three-value enum is almost certainly a mistake, and the silent
  alternative scans baseline and returns zero rows. Non-EQUALS on
  `root` is allowed as a post-filter.
- **D2 — truncated scans get a `scan_truncated` column and are not
  cached.** Named `scan_truncated` rather than `truncated` for clarity
  at the SQL prompt.
- **D3 — per-key singleflight** via `golang.org/x/sync/singleflight` in
  the nested module. Unrelated queries must not block each other.
- **D4 — knobs travel as `BEAGLE_*` env vars.** Rejected: a config file
  (more machinery than five knobs justify) and manual non-autoload
  launch (a second daemon lifecycle to manage).
- **D5 — dropped 13 constant/derivable columns; `profile`/`root` made
  hidden + index.** `record_type`, `record_id`, `schema_version`,
  `scanner_name`, `scanner_version`, `run_id`, `scan_time`,
  `endpoint_hostname`, `endpoint_os`, `endpoint_arch`, `endpoint_uid`,
  `endpoint_device_id`, and `project_path` were either constant across
  an entire scan (identity/run, most of `Endpoint`) or derivable from
  `root`/`root_kind` (`project_path`). None of them help a query author
  filter, group, or scope a result; they only added width to every row
  and pushed serialized results closer to the Thrift `MaxMessageSize`.
  `profile` and `root` stay as constraint inputs but no longer clutter
  `SELECT *`, since their main use is scoping the scan rather than
  reading back per-row. `model.Record` is unchanged — this is a
  table-projection decision, not a record-shape change, so the CLI's
  NDJSON output is unaffected.
- **D6 — `ecosystem` filter pushed down before row-building.** An
  EQUALS constraint on `ecosystem` drops non-matching records from the
  scan outcome before they are mapped to rows and serialized. A
  single-ecosystem query over a large scan no longer pays the
  Thrift-serialization cost of every other ecosystem's rows just to
  have SQLite discard them afterward. This narrows what gets
  serialized, not what gets walked — the residual risk of an
  otherwise-broad `deep` scan approaching `MaxMessageSize` is
  documented qualitatively in `osquery/README.md`'s "Scoping queries"
  section rather than pinned to a number, since the actual result size
  depends on the endpoint being scanned.
- **D7 — `beagle_distinct_packages` dedupes on every column but
  `source_file`, replacing it with `install_count` + `source_files`.**
  A second table, not a query-time `GROUP BY`, because osquery's
  virtual-table layer has no aggregate support to lean on — the dedup
  has to happen in Go before rows are handed back. Two records collapse
  into one row only when every other column matches; the distinct row
  swaps the single `source_file` for `install_count` (how many distinct
  install locations collapsed into it) and `source_files` (their sorted,
  de-duplicated JSON array), so per-location detail is still reachable,
  just aggregated instead of one row per location. `DistinctColumns()`
  derives from `Columns()` by dropping `source_file` and appending the
  two new columns, rather than maintaining a second column list by
  hand, so the two tables' shared columns cannot drift out of lockstep.
  Both tables run through the same `scanForQuery` constraint-resolution
  step and the same `ScanFunc`/cache — `beagle_distinct_packages` is a
  different row-shaping step over the identical scan outcome, not a
  different scan. Querying one table warms the shared cache for the
  other.

## Deferred, additive

Threat-intel / exposure findings are not exposed by this phase. Adding
them later is a separate `beagle_findings` table running the same
bridge with `Config.Catalog` set, collecting `record_type == "finding"`
lines. `beagle_packages` and its columns do not change when that lands.

`scan_summary` and `diagnostic` records are deliberately not table
rows. `Run` emits no summary through this path and diagnostics go to
the extension log. A future `beagle_scan_status` table could surface
summaries if a need appears — not built now.

## Testing approach

- `table/packages_test.go`: drive `Generate` against the existing
  `cmd/beagle/selftest/fixtures` tree with a `root=` constraint. Assert
  mapped rows include the fixture packages and the typed specials map
  correctly. Assert an unknown `profile`, a non-EQUALS `profile`
  operator, and a broad-home-root-under-baseline all surface errors.
  Assert a trailing-slash `root` constraint round-trips byte-for-byte.
  Assert the row map has no cell for any of the 13 dropped columns
  while `endpoint_username` is retained; assert `profile` and `root`
  report `Hidden`/`Index` true from `Columns()`; assert an `ecosystem`
  EQUALS constraint (single value and multi-value) filters the row set
  and a non-EQUALS operator does not, without mutating the underlying
  scan outcome.
- `scan_test.go`: NDJSON → `[]model.Record` round-trip, including
  `DirectDependency` nil vs true vs false and a non-empty
  `LifecycleScripts`.
- `cache_test.go`: TTL hit within window, miss after expiry, per-key
  isolation, concurrent same-key sharing one scan, a scan in flight for
  key A not blocking key B, truncated results returned but not cached.
- Integration against an installed osqueryi: pin the
  empty-string-as-NULL coercion and the per-value `IN` dispatch.

---

# Walker excludes: marketplace catalog trees

**Status: fixed** (`internal/walk/walk.go`, covered by
`TestWalkSkipsMarketplaceCatalogTrees`).

Plugin-marketplace *catalog clones* were being reported as installed
inventory. These are local checkouts of browsable plugin directories
whose `.mcp.json` files and lockfiles are install templates, not
configuration that runs on the endpoint.

**Scope.** On a reference macOS endpoint with Claude Code, Claude
Desktop, and Codex present, over half of emitted `mcp` records traced to
marketplace catalogs across three products with the same clone
pattern:

- `~/.claude/plugins/marketplaces/<mkt>/` — Claude Code
- `.../cowork_plugins/marketplaces/` — Claude Desktop cowork sessions
- `~/.codex/.tmp/` — Codex bundled-catalog staging

The pollution was not MCP-only: marketplace clones are full git
checkouts, so npm picked them up too, emitting records from catalog
`package-lock.json` and `bun.lock` files for dependency trees the user
never chose or installed.

**Why it's the common case, not an artifact.** Claude Code's docs state
the official marketplace is registered automatically the first time you
start it interactively, so essentially every user has that catalog
cloned locally. The same docs confirm a plugin's `.mcp.json` is read
only from an *installed, enabled* plugin's root — catalog copies are
inert. Cross-checking `installed_plugins.json` on the reference
endpoint confirmed none of the cataloged plugins were installed.

**Root cause.** `internal/roots/roots.go` classifies the whole
`~/.claude` tree as one `RootKindMCPConfig` root, and
`DefaultExcludes` had no entry distinguishing `plugins/marketplaces/`
from `plugins/cache/`, so every `.mcp.json` under either path was
emitted as a configured server.

**Fix: anchored entries in `walk.DefaultExcludes`.**

1. Excluding at the walker fixes every ecosystem at once (MCP records
   plus the npm pollution plus anything future) using the mechanism
   that already exists for exactly this job — suffix-component
   excludes, which support anchored multi-component entries like
   `Library/Caches`.
2. Entries are anchored (`.claude/plugins/marketplaces`,
   `cowork_plugins/marketplaces`, `.codex/.tmp`), not a bare
   `marketplaces` component, so a user project directory that happens
   to be named `marketplaces` is unaffected.
3. `~/.claude/plugins/cache/` keeps being walked — it holds genuinely
   installed plugins whose root `.mcp.json` is load-bearing.
4. Failure mode is safe: if a product changes its catalog layout, the
   exclude stops matching and scans regress to the old noise. Real
   inventory is never lost. A new catalog layout gets its own anchored
   entry rather than a broadened pattern.

**Rejected alternatives.** Cross-referencing
`installed_plugins.json` couples the scanner to a private manifest
format, does nothing for the cowork and Codex catalogs (which have no
such manifest), and is unnecessary since the installed set is already
independently visible under `plugins/cache/`. Skipping only in the MCP
scanner would leave the npm pollution in place.

**Accepted imprecision.** Non-root `.mcp.json` files nested inside an
*installed* plugin (cross-agent setup templates a plugin ships as data)
are still emitted. The plugin is genuinely installed, the count is
small, and distinguishing plugin-root from nested files would couple us
to plugin-layout details for little gain. Revisit only if it produces a
real false exposure match.

---

# Release wiring

Open, blocked on the first core tag:

- Add `require github.com/packagebeagle/beagle vX.Y.Z` to
  `osquery/go.mod` and tidy.
- Add a goreleaser build entry with `dir: osquery` producing
  `beagle.ext`, with `-X` ldflags for `scanner_version` like the
  existing CLI entry.
- The goreleaser `before` hook runs `go mod tidy` at the repo root
  only; add one for `osquery/`.

Already wired: CI creates the gitignored `go.work` overlay and runs
`gofmt`, `vet`, `test -race`, and `build` for the nested module
alongside the core (`.github/workflows/ci.yml`).

# beagle — design record

Why the project is shaped the way it is, and the decisions a contributor
would otherwise have to reverse-engineer or re-litigate. Per-ecosystem
on-disk detail lives in [inventory-sources.md](inventory-sources.md);
record shapes live in [state-model.md](state-model.md) and
[schema/](schema/).

## Core invariants

**The core module has exactly one non-stdlib dependency, and adding a
second needs the same argument this one had to win.** beagle reads
attacker-plantable files on endpoints during incident response; every
dependency is attack surface and a supply-chain link in a tool whose
job is auditing supply chains. The single exception is
`github.com/charlievieth/fastwalk` — MIT, no transitive dependencies,
pure-stdlib syscalls — which makes a deep scan ~3.5x faster (see
"Parallel traversal" below). Anything else third-party goes in the
nested `osquery/` module, never in the root module.

A `-tags nofastwalk` build drops even that one, at the cost of the
speedup. It exists so an operator who needs beagle to link no
third-party code at all still has a supported build.

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

**Content capture is confined to `agent-config`, behind a redactor.**
Every other scanner records identity, never content: MCP env values are
dropped and key names are not retained, remote URLs are cut to
`scheme://host`, local skill paths are dropped, and `.env` / `.envrc`
are skipped outright. `beagle_agent_config` breaks that pattern on
purpose — a hook row that does not say what the hook runs cannot support
pattern-based detection. Every captured string passes through
`agentcfg.Redact` or `agentcfg.RedactCommand` first. Those match on
variable name and known credential formats, both denylists that fail
open, so a Shannon-entropy floor backs them up for formats nobody
enumerated. Redaction preserves shape
(`redacted:format:github-pat(40)`) rather than erasing the value, so
detection rules keep their signal. Do not add a capture path to this
package that bypasses the redactor.

**`VERSION` is hand-synced into two places.** `cmd/beagle/version.go`
and `osquery/version.go` each carry a `fileDefault` constant that must
match the `VERSION` file. Neither reads the file at build time (the
ldflags path is what release builds use; `fileDefault` is the
`go build` fallback). Bumping `VERSION` without touching both is the
easiest mistake to make in this repo.

## Module layout: the nested osquery module

osquery-go pulls in Apache Thrift and a transitive tree behind it,
which the root module will not carry. So the
extension is a **separate Go module** at `osquery/`, with its own
`go.mod`.

It imports the core's `internal/` packages directly. This is legal:
Go's `internal/` visibility is a **path-prefix** rule, and
`github.com/packagebeagle/beagle/osquery` is under the
`github.com/packagebeagle/beagle` prefix. Verified empirically, not
assumed.

The result: the core module's dependency list stays at one line, and
only the nested module carries osquery-go, Thrift, and
`golang.org/x/sync`.

Local development uses a **gitignored** root `go.work`:

```sh
go work init . ./osquery   # once per checkout
```

It is gitignored by design — do not commit it. The release workflow
recreates the same overlay (`go work init . ./osquery`) before running
GoReleaser, so the nested module resolves the core's `internal/`
packages the same way CI's test job does. The nested `go.mod` carries
no `require`/`replace` on the core, and no `replace` directive is ever
committed.

**No public library yet.** Promoting packages out of `internal/` is
deferred until there is a real external consumer. The osquery
extension is the first consumer and will teach us the right API
surface. Do not promote speculatively.

**The record seam.** `scanner.Run(ctx, cfg)` pushes records through a
concrete `*output.Emitter`. The extension builds its emitter with
`output.NewCollector`, a mode that accumulates package records as
values instead of encoding them, and reads them back with
`Collected()`. The extension previously encoded to NDJSON and decoded
the buffer straight back; the collector removes that serialize/parse
round-trip from every osquery query. It is still one concrete type, not
an interface — extract an `Emitter` interface only when there's a
second reason to. A collector has no records writer, so `EmitFinding`
and `EmitSummary` return an error rather than dropping a record; the
extension passes no `Catalog` and emits no summary.

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
   only projects 19 of its fields (D5); the rest are carried on the
   collected records unused by the table. `scanner_version`
   comes from the nested module (it cannot import `cmd/beagle`):
   injected via goreleaser `-X` ldflags with a `debug.ReadBuildInfo`
   fallback, mirroring the CLI's `currentVersion()` rather than adding
   a third hand-synced version constant.
2. Create `output.NewCollector(diagWriter, runID)` — the emitter mode
   that accumulates package records in memory — with a diag writer
   forwarding to the extension's stderr / osquery log.
3. Call `scanner.Run(ctx, cfg)` with `Catalog: nil`,
   `FindingsOnly: false`, `MaxDuration` per profile, and the resolved
   roots. **`MaxFileSize` must be set explicitly** to the CLI's 5 MiB
   default: `scanner.Run` has no default of its own and
   `fsread.Bounded` treats `<= 0` as *unbounded*, which is a memory
   hazard in a resident process reading attacker-plantable files.
4. Read the accumulated `[]model.Record` back with `Collected()`,
   returning them with the resolved `[]scanner.Root` (needed for the
   `root` output column) and the `Truncated` flag.

With no catalog, only package records are emitted and `Run` emits no
scan_summary, so the collector holds package records only — the two
calls a collector cannot serve are the two the bridge never makes.

## Caching and bounds (`cache.go`)

- **TTL cache** keyed on `profile + "\x00" + roots sorted and joined
  with "\x00"` (NUL cannot appear in paths), memoizing decoded records,
  resolved roots, and the truncated flag for `BEAGLE_CACHE_TTL`
  (default 60s). Repeated queries and osquery health probes inside the
  window reuse the last scan instead of re-walking the filesystem.
- **`MaxDuration` defaults are per profile** (see `scanBudget`), not a
  single global value, so one scan cannot hang the daemon while a deep
  incident sweep still gets a budget it can realistically finish in. A
  single baseline-sized default would leave most deep queries
  truncated. Query authors choose the profile and therefore the budget;
  the semaphore bounds what that can occupy.
- **Truncated scans are returned but not cached**, each row carrying
  `scan_truncated = 1`, so the next query retries rather than serving
  partial-as-complete for the whole TTL (D2).
- **Per-key singleflight, not a global mutex** (D3). The lock covers
  only map access. Concurrent queries for the same key wait on and
  share one scan; different keys proceed independently. A global mutex
  held across a multi-minute scan would stall every other query on the
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
- The generate request's context JSON carries `colsUsed` (and
  `colsUsedBitset`) alongside `constraints`. `osquery-go` drops both:
  its `queryContextJSON` declares a field for `constraints` and nothing
  else, so `json.Unmarshal` discards the rest. Probed with a five-column
  table:

  | query shape | `colsUsed` |
  |---|---|
  | `SELECT col_a, col_c WHERE col_b='b'` | `[col_a, col_b, col_c]` |
  | `SELECT *` | all five |
  | `SELECT col_a` | `[col_a]` |
  | `count(*)` | `[]` |
  | `count(*) WHERE col_b='b'` | `[col_b]` |
  | `WHERE hid='h'` (hidden column) | includes `hid` |
  | `ORDER BY col_e` (unselected) | includes `col_e` |

  Columns a query only constrains or orders by are listed, hidden ones
  included, which is what makes projecting to the set safe (D8).
- Worker memory tracks returned *cell count*, not payload bytes:
  ~152 bytes per cell, measured across seven runs. Each row arrives as
  a Thrift `map<string,string>` and is materialized as a
  `std::map<std::string, std::string>`, so per-cell allocator and
  map-node overhead dominates and cell contents are a minor term.
- The binding size ceiling is the watchdog's 200 MB worker RSS limit,
  not Thrift's 100 MB `MaxMessageSize`. Exceeding it SIGKILLs the
  worker; the extension socket then EOFs mid-call and osquery reports
  the symptom as `Extension call failed: No more data to read`.

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
  depends on the endpoint being scanned. (D5 and D6 both named
  `MaxMessageSize` as the ceiling. Later measurement found the binding
  limit is the watchdog's 200 MB worker RSS — roughly 4x tighter — and
  that it tracks cell count rather than payload bytes; see "Verified
  osquery behavior" and D8. Both decisions still hold, for a reason
  that turned out to be stronger than the one recorded.)
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
- **D8 — every table returns only the columns a query reads, recovered
  from `colsUsed`.** Rows are `map[string]string`, so a table can
  return fewer cells than it declares columns — the absent ones read as
  NULL, and a query that did not ask for them never looks. Confirmed
  end to end with a differential test over a 47,171-row scan: the
  projected path and the `SELECT *` path returned identical values for
  every column in common. Measured on a `deep` scan of
  a developer `/Users` (503,448 npm records collapsing to 68,263
  `beagle_distinct_packages` rows): a four-column `SELECT` dropped from
  19 cells per row to 6 and peak worker RSS from 237.5 MB to 99.7 MB,
  same 68,263 rows. Verified above to include selected, constrained
  (hidden columns included), and `ORDER BY` columns, so projection
  cannot break SQLite's re-verification of `WHERE` predicates against
  the returned rows — the failure mode that would otherwise discard
  every row silently. Absent `colsUsed` means "return every column", so
  an osquery build that does not send it degrades to the previous
  behavior rather than to empty rows; an empty list is a real answer
  (`count(*)` reads no columns) and yields cell-less rows.
  **This is per-query, not a bound.** `SELECT *` correctly reports all
  19 columns, has nothing to trim, and still measures 238.1 MB. It
  narrows the failure class to wide queries rather than eliminating it;
  a returned-cell budget that stops and sets `scan_truncated = 1` is the
  complementary fix and the only one that bounds memory regardless of
  which columns are requested. Extension-side memory is untouched
  (~1.5 GB holding the scan's records, ~919 MB under
  `GOMEMLIMIT=256MiB`, with a ~900 MB live-set floor); the watchdog
  killed only workers, never the extension.
- **D8a — dedup grouping uses the unprojected row.** `dedupeRows`
  builds the complete row, computes `distinctKey` from it, and trims
  cells only on the way out. Grouping the projected row instead would
  collapse records differing solely in an unselected column, making
  `install_count` depend on the query's `SELECT` list.
- **D8b — a wrapper implementing `OsqueryPlugin`, not a fork of
  `osquery-go`.** The library drops one additive field; everything else
  about its table plugin is what we want. `osquery/colsused.go`
  intercepts `action=generate`, parses `colsUsed` out of the raw
  request, and attaches it to the Go context before delegating.
- **Rejected: `LIMIT`/`OFFSET` pushdown.** osquery does forward them as
  constraint operators 73 and 74
  (`SQLITE_INDEX_CONSTRAINT_LIMIT`/`OFFSET`), which `osquery-go` does
  not model. Honoring them corrupts results: osquery never claims the
  constraint in `xBestIndex`, so SQLite applies the limit a second time
  over the already-capped rows. Measured: `WHERE val LIKE 'keep'`
  returned the correct 10 rows, `… LIMIT 5` returned 0 (capped before
  filtering) and `LIMIT 5 OFFSET 42` returned 0 (offset applied twice).
  The constraint is visible but not claimable; implementing it ships
  silent data loss.
- **Rejected: streaming or paging the response.** The extension
  protocol has no cursor — `generate` is one Thrift call returning the
  complete row set, and `osquery-go`'s "buffered" support is
  transport-level write batching, not result streaming. Caller-driven
  paging via a `page` EQUALS column does work (the scan cache makes
  successive pages nearly free) but needs an orchestration loop Fleet
  does not provide, and pages skew if the cache expires mid-iteration.
- **Rejected: handing osquery a side SQLite file.** Blocked at
  osquery's `sqlite3_set_authorizer()` callback, which denies
  `SQLITE_ATTACH` (action 24) and `PRAGMA` (19). No flag relaxes it.
- **Rejected: shortening column names on the wire.** Names were the
  larger half of the payload (15.4 MB of keys vs 6.2 MB of values at 19
  columns), but projection cuts both proportionally.

## Deferred, additive

Threat-intel / exposure findings are not exposed by this phase. Adding
them later is a separate `beagle_findings` table running the same
bridge with `Config.Catalog` set, collecting `record_type == "finding"`
lines. `beagle_packages` and its columns do not change when that lands.

- **Codex TOML surfaces.** `[shell_environment_policy]`, `notify`,
  `[projects."path"] trust_level`, `/etc/codex/config.toml`, and the
  `/etc/codex/requirements.toml` + `managed_config.toml` enterprise
  layer. A real Codex config needs array-of-tables, inline tables,
  quoted dotted headers, integers, and booleans — a near-complete TOML
  parser in a module held to one dependency. Codex hooks are covered
  through `hooks.json` instead. Note that even a parser would not give
  full enterprise coverage: macOS MDM delivers policy as base64 TOML in
  the `com.openai.codex` preference domain, and cloud policy never
  touches disk.

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
- `table/colsused_test.go`: assert projection keeps exactly the named
  columns; that a nil set (no `colsUsed` sent) keeps every column and an
  empty one drops every cell; and — the D8a invariant — that two records
  differing only in an *unselected* column stay two
  `beagle_distinct_packages` rows with `install_count = 1` each.
  Projecting before grouping instead of after makes that last test fail,
  which is the whole reason it is there.
- `colsused_test.go`: parse `colsUsed` out of a context JSON captured
  from osqueryd 5.23.1 (field present, absent, empty, malformed), and
  drive the wrapped plugin's `Call` end to end — a `generate` request
  with `colsUsed` comes back projected, one without comes back whole,
  and the `columns` action plus `Name`/`RegistryName` still delegate.
- `scan_test.go`: NDJSON → `[]model.Record` round-trip, including
  `DirectDependency` nil vs true vs false and a non-empty
  `LifecycleScripts`.
- `cache_test.go`: TTL hit within window, miss after expiry, per-key
  isolation, concurrent same-key sharing one scan, a scan in flight for
  key A not blocking key B, truncated results returned but not cached.
- Integration against an installed osqueryi: pin the
  empty-string-as-NULL coercion and the per-value `IN` dispatch.

---

# Parallel traversal

**Status: default** (`internal/walk/walk_fastwalk.go`, covered by
`TestWalkParallelSurvivesUnreadableDirectory` and
`TestWalkParallelMatchesSerialOnOverlappingRoots`).

The walker drives traversal with
[charlievieth/fastwalk](https://github.com/charlievieth/fastwalk),
which reads directories from a pool of goroutines. `-tags nofastwalk`
swaps in the stdlib `filepath.WalkDir` traversal
(`internal/walk/walk_serial.go`) and links no third-party code.

**Why it was worth a dependency.** The scan was traversal-bound, not
parse-bound. On a reference macOS endpoint (10 cores, `/Users/s` =
1.81M files / 300K dirs after excludes, hot cache), a deep scan spent
~14s of `sys` in `readdir`/`stat` against ~4s of `user` parsing that
already overlapped underneath it. Parallelizing the one serial stage
moved the whole wall clock:

| | isolated traversal | end-to-end deep scan |
|---|---|---|
| `filepath.WalkDir` | 32.9s | 31.1s / 29.4s |
| fastwalk | 8.2s | 8.7s / 8.2s |

Parity was verified rather than assumed: identical `record_id` sets
(22,055, zero diff) on a subtree, identical `files_considered`
(1,814,086) and package counts (58,102) on the full tree, and `-race`
clean in both modes. The 4-worker parse pool and the single-threaded
emitter did not become the new bottleneck.

**What it cost.** One MIT-licensed leaf module with zero transitive
dependencies and no cgo. That is the smallest dependency the core could
have taken, and a one-shot IR scan dropping from 30s to 8s changes
whether operators are willing to run it on a fleet. `nofastwalk`
keeps the zero-dependency build available for anyone who values that
over the speedup.

**The concurrency contract moved to the caller.** `walk.Walk` now
invokes the `Visitor` and `OnError` from several goroutines. The
scanner was already safe — the emitter is mutex-guarded and
`filesConsidered` is an `atomic.Int64` — but any new caller has to be,
and test visitors that append to a bare slice are a data race under the
default build.

**Two fastwalk error semantics differ from `WalkDir` and the callback
compensates for both.** They are commented at the call site because
each one silently truncates a scan rather than failing loudly:

1. *A directory error must return `nil`, never `SkipDir`.* fastwalk
   calls back with a non-nil error only after `readDir` has already
   failed, and hands that return value straight to its coordinator
   loop, which aborts the whole walk on any non-nil error — `SkipDir`
   included. The first version of this code returned `SkipDir` there
   and truncated the traversal at the first unreadable directory. A
   single TCC denial on macOS was enough, which is precisely the
   condition `DefaultExcludes` exists to manage. A probe measured
   truncation in 64 of 200 runs, down to 49 of 83 entries.
2. *A callback's own return value comes back as an `err` argument.*
   Once `readDir` unwinds, fastwalk calls the callback a second time
   for the same directory, passing what the callback returned as the
   error. Anything the error branch logs-and-swallows is therefore
   silently discarded — which is how the first attempt at `ErrStop`
   ended up reported as a warning while the walk carried on through
   every remaining root. `ErrStop` is re-returned from the error branch
   for exactly this reason; the regression test is
   `TestWalkErrStopEndsEveryRoot`.

**The Visitor error contract, and why `ErrSkip` on a file is refused.**
Three sentinels, applied identically by both traversals through the
shared `onVisitError`:

| return | meaning |
|---|---|
| `ErrSkip` on a **directory** | prune that subtree |
| `ErrSkip` on anything else | refused: reported through `OnError`, walk continues |
| `ErrStop` | end the walk, remaining roots included; `Walk` returns nil |
| any other error | reported through `OnError`, walk continues |

The refusal is there because the two traversals cannot agree on what a
file-level skip means. `filepath.WalkDir` abandons the rest of the
containing directory, subdirectories included. fastwalk abandons only
what it has not dispatched yet: measured on a tree of twelve sibling
subtrees, a single file-level `SkipDir` let some siblings through and
lost the rest, non-deterministically, while also surfacing a bogus
`skip this directory` error against the parent. Neither behavior is
worth having and no scanner wants it, so refusing it costs nothing and
buys exact parity between the builds. Cancellation and emit failure —
the only two cases that ever needed to stop a walk from a file — use
`ErrStop`, which means what it says.

**Inode dedup stays unconditional.** Gating it to Linux (on the theory
that bind mounts are the only way to reach one directory by two paths)
was proposed and rejected. The `seen` map's everyday job is collapsing
**overlapping roots**, which is platform-independent: `beagle roots`
resolves both `~/.cursor` and `~/.cursor/extensions` on a stock macOS
endpoint, and without dedup the inner tree is walked twice —
`files_considered` 16,025 against the serial path's 8,101, on a summary
operators compare across hosts. The saved work is also unmeasurable:
over `~/go` (37,417 dirs), dedup on versus off was pure noise across
five paired runs.

**Rejected: a hand-rolled parallel `WalkDir` in-tree.** Parallelism is
the entire win, so a stdlib-only version was on the table and would
have preserved the zero-dependency invariant. It loses because the
subtle part is not the goroutine pool but the error and `SkipDir`
semantics above — the exact code that has already produced one
silent-truncation bug. Owning that in-tree trades a 200-line audited
dependency for 200 lines of our own with the same failure modes and
less exposure.

**Rejected: de-nesting roots.** Dropping roots that are nested inside
other roots, once, in `Walk`, sounds like it would remove a double-walk.
It would not: the dedup map already stops the nested root at its *first*
directory, one `dirKey` stat and then `SkipDir` over the whole thing.
Timed on `~/go` with and without a nested second root, three runs each,
the difference is noise (0.80/0.84/0.83s against 0.81/0.84/0.83s) and
`files_considered` is identical at 235,173. There is no double-walk left
to remove.

It also would not replace the dedup map, which is the other thing that
makes it tempting. Lexical prefix matching does not catch a symlinked
root, a bind mount, or `~/Code` against `~/code` on a case-insensitive
APFS volume; `seen` has to stay for those. Revisit only with a profile
showing per-directory `stat` actually costing something.

Two things worth knowing if it is ever revisited: attribution is already
decoupled, so it stays a small change — `newRootKindLookup` and the
osquery `newRootPathLookup` both take the full configured root list
independently of what gets walked, so dropping a root from traversal
cannot change `root_kind` or the `root` column. And the obvious
implementation is wrong: sorting the roots does not make descendants
contiguous after their parent (`/a-b` sorts between `/a` and `/a/b`), so
a single-cursor sweep leaks nested roots and the check has to run
against every kept root.

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

A pushed `v*` tag runs `.github/workflows/release.yml`, which recreates
the `go.work` overlay (`go work init . ./osquery`) and then runs
GoReleaser (`--clean`, drafting the release). `.goreleaser.yaml` builds
two binaries for darwin/linux × amd64/arm64:

- `beagle` from `./cmd/beagle`, archived as
  `beagle_<ver>_<os>_<arch>.tar.gz` (LICENSE, NOTICE, README,
  `threat_intel/**`).
- `beagle.ext` from the nested module (`dir: osquery`), archived as
  `beagle-osquery_<ver>_<os>_<arch>.tar.gz` (LICENSE, NOTICE, the
  extension README). Both binaries take `-X main.Version={{.Tag}}` so
  `scanner_version` reflects the tag.

The osquery build resolves the core's `internal/` packages through the
workspace overlay — the nested `go.mod` needs no `require`/`replace` on
the core, and GoReleaser must not run with `GOWORK=off`. The `before`
hook runs `go mod tidy` at the repo root only; the osquery module needs
no tidy step because the overlay, not a `require`, supplies the core.

Already wired: CI creates the gitignored `go.work` overlay and runs
`gofmt`, `vet`, `test -race`, and `build` for the nested module
alongside the core (`.github/workflows/ci.yml`).

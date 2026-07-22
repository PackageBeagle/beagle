# beagle osquery extension

`beagle.ext` exposes beagle's package/extension/dev-tool inventory to
osquery as a SQL table, `beagle_packages`. Each query runs (or serves
from a short-lived cache) one read-only scan of the constrained
profile and roots — the same scan the `beagle` CLI performs, wired
through the same internal packages.

This directory is a nested Go module. The core module stays
zero-dependency; only this module carries
[osquery-go](https://github.com/osquery/osquery-go) (and its Thrift
dependency) plus `golang.org/x/sync`.

Design and verified osquery behavior:
[docs/DESIGN.md](../docs/DESIGN.md).

## Schema

`beagle_packages` has 19 columns, one row per package/extension/dev-tool
record:

| column | type | note |
|---|---|---|
| `endpoint_username` | TEXT | varies per row under `BEAGLE_ALL_USERS` |
| `ecosystem` | TEXT | |
| `package_name` | TEXT | |
| `normalized_name` | TEXT | |
| `version` | TEXT | |
| `root_kind` | TEXT | |
| `install_scope` | TEXT | |
| `package_manager` | TEXT | |
| `source_type` | TEXT | |
| `source_file` | TEXT | |
| `confidence` | TEXT | |
| `requested_spec` | TEXT | |
| `server_name` | TEXT | |
| `direct_dependency` | INTEGER | tri-state: 1, 0, or NULL when the source format does not record directness |
| `has_lifecycle_scripts` | INTEGER | 0/1 |
| `lifecycle_scripts` | TEXT | JSON array |
| `profile` | TEXT | hidden + index: usable in `WHERE`, absent from `SELECT *`. Equality only; absent defaults to `baseline`. |
| `root` | TEXT | hidden + index: usable in `WHERE`, absent from `SELECT *`. On output, the enclosing configured root for that row, byte-for-byte as configured. |
| `scan_truncated` | INTEGER | 1 if the scan hit its time budget and returned partial results |

`profile` and `root` still work as ordinary filter columns in `WHERE`
even though `SELECT *` won't show them — that is what "hidden" means to
osquery's virtual-table layer, not a restriction on querying them.

## Build

Requires Go 1.26+ (forced by osquery-go). From a repo checkout, the
gitignored workspace resolves the core module:

```sh
cd <checkout>
go work init . ./osquery   # once per checkout
cd osquery
go build -o beagle.ext .
go test ./...
```

osquery requires the `.ext` suffix on extension executables.

## Load

Ad hoc, in an osqueryi shell:

```sh
osqueryi --extension /path/to/beagle.ext
```

Under osqueryd, list the binary in the extensions autoload file:

```sh
echo "/usr/local/lib/osquery/extensions/beagle.ext" >> /etc/osquery/extensions.load
```

osqueryd requires autoloaded extension binaries to be owned by root
and not writable by others (osqueryi accepts `--allow_unsafe` for
development). osquery controls the extension's argv; the only flags it
passes are `--socket`, `--timeout`, `--interval`, and `--verbose`. All
beagle-specific configuration is environment variables, set on the
process that launches osqueryd.

## Query

```sql
-- curated baseline inventory (default profile)
SELECT package_name, version, ecosystem FROM beagle_packages;

-- explicit project root, still baseline guardrails
SELECT * FROM beagle_packages WHERE root = '/Users/me/code';

-- named profile
SELECT * FROM beagle_packages WHERE profile = 'project';

-- incident sweep of a home dir (deep profile, 120s budget)
SELECT * FROM beagle_packages WHERE profile = 'deep' AND root = '/Users/me';

-- post-filter over default roots (no scope change)
SELECT * FROM beagle_packages WHERE root LIKE '/Users/%';
```

Semantics:

- `profile` and `root` are input constraints as well as output
  columns. `profile` accepts only `=` (baseline, project, deep;
  absent means baseline); any other operator on it is an error rather
  than a silently empty result. `root = ...` values become explicit
  scan roots; other operators on `root` do not change scan scope and
  act as ordinary SQL filters over the default-profile scan.
- The profile guardrails match the CLI: baseline/project refuse broad
  home roots (use `deep`), and `deep` requires at least one explicit
  root.
- `root IN ('/a','/b')` is dispatched by osquery as one scan per
  value.
- `direct_dependency` is tri-state: 1, 0, or NULL when the source
  format does not record directness. `WHERE direct_dependency IS NULL`
  works.
- `scan_truncated` is 1 on every row of a scan that hit its time
  budget and returned partial results. Truncated results are never
  cached, so the next query retries.
- Every other column mirrors a field of beagle's package record (see
  the [Schema](#schema) table above, or `.schema beagle_packages` in
  osqueryi).

## Scoping queries

Every column beagle emits for a query has to be serialized over Thrift
and fit under its `MaxMessageSize` (100 MB by default). `profile` and
`root` already narrow the filesystem walk; `ecosystem` narrows the
result set further by dropping non-matching records before they are
serialized. For a `deep` scan of a large tree, constrain one or both:

```sql
SELECT * FROM beagle_packages
WHERE profile = 'deep' AND root = '/Users/me' AND ecosystem = 'pypi';
```

Residual risk: a broad, single-ecosystem `deep` scan of a large home
directory can still approach the Thrift limit even with an `ecosystem`
constraint, because the constraint filters which records get
serialized, not how much of the filesystem gets walked first. If a
query is at risk of hitting the limit, narrow `root` further (a project
subtree rather than the whole home directory) or add an `ecosystem`
constraint if the query doesn't already have one.

## Configuration

Environment variables on the osqueryd (or osqueryi) process:

| variable | default | meaning |
|---|---|---|
| `BEAGLE_CACHE_TTL` | `60s` | How long one scan's results serve repeated queries for the same profile+roots. `0` disables caching. |
| `BEAGLE_MAX_DURATION` | unset | Overrides the per-profile scan budget for every profile. Unset uses the defaults: baseline 30s, project 60s, deep 120s. |
| `BEAGLE_ALL_USERS` | `false` | macOS only: expand baseline/project default roots across every real user home under `/Users`. Not valid with explicit `root` constraints or `deep`. |
| `BEAGLE_USERS_DIR` | `/Users` | Override the users directory for `BEAGLE_ALL_USERS` (testing / non-standard layouts). |
| `BEAGLE_DEVICE_ID_ENV` | unset | Name of another env var whose value is resolved into the endpoint's device id internally, matching the CLI's `--device-id-env` (never a literal id). `beagle_packages` does not currently have a device-id column, so this knob has no visible effect on query results. |

Invalid values fail extension startup with an error naming the
variable.

`BEAGLE_MAX_DURATION` must exceed how long the actual scan takes, or
the scan is truncated (`scan_truncated = 1`, partial rows) before it
finishes. Widening it for a deep incident sweep:

```sh
BEAGLE_MAX_DURATION=180s osqueryi \
  --extension /path/to/beagle.ext \
  --allow_unsafe \
  --thrift_string_size_limit=0
```

`--allow_unsafe` is osqueryi's development-mode flag for
non-root-owned extension binaries (see Load, above).
`--thrift_string_size_limit=0` removes osquery's own string-size guard
so a wide `SELECT *` over a large scan isn't rejected client-side
before `MaxMessageSize` would even come into play.

For a launchd-managed osqueryd, set them in the daemon plist:

```xml
<key>EnvironmentVariables</key>
<dict>
  <key>BEAGLE_CACHE_TTL</key><string>120s</string>
  <key>BEAGLE_DEVICE_ID_ENV</key><string>MDM_DEVICE_ID</string>
</dict>
```

`/Library/LaunchDaemons` plists are root-owned: non-admin users cannot
modify or read a root daemon's environment, so MDM-pushed values are
as tamper-resistant as osquery's own flagfile.

## Running as root: what a default query covers

Under osqueryd (root), the baseline profile's per-user default roots
expand from the process owner's home — that is `/var/root`, not the
machine's user homes. A default `SELECT * FROM beagle_packages`
therefore covers system/Homebrew roots plus root's own home, and very
little developer state.

To cover user homes:

- macOS: set `BEAGLE_ALL_USERS=1` to expand the defaults across every
  real home under `/Users`.
- Linux: `BEAGLE_ALL_USERS` is not supported. Enumerate homes in the
  query instead, e.g. `WHERE profile = 'deep' AND root = '/home/<user>'`
  per user (deep profile, because bare home directories are refused by
  baseline/project).

## Behavior and bounds

- One scan per distinct (profile, roots) constraint set, cached for
  `BEAGLE_CACHE_TTL`. Concurrent queries for the same key share one
  scan; different keys do not block each other; at most 2 scans run
  at once.
- Scans are bounded by the per-profile time budget and a 5 MiB
  per-file read cap. A scan that hits its budget returns what it found
  with `scan_truncated = 1`.
- Scan diagnostics and root-resolution notes go to the extension's
  stderr (osqueryd captures it in its logs); they are never table
  rows. Exposure findings (`beagle_findings`) are a planned separate
  table and not part of `beagle_packages`.

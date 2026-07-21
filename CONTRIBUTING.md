# Contributing to beagle

Thanks for your interest. This project favours small, focused changes
with tests.

[`docs/DESIGN.md`](docs/DESIGN.md) records why the project is shaped the
way it is — the zero-dependency core, the nested osquery module, the
osquery table semantics, and open issues with a decided fix shape. Read
it before changing module layout, the `beagle_packages` table, or the
walker's exclude list.

## Local development

Requires Go 1.25+. No non-stdlib runtime dependencies.

The osquery extension in `osquery/` is a separate Go module, so it
needs a workspace overlay to resolve the core locally:

```sh
go work init . ./osquery   # once per checkout; gitignored, never commit
```

```sh
go build ./cmd/beagle
go test ./...
go test -race ./...
go vet ./...
gofmt -l .   # should print nothing
./beagle selftest
```

## Pull requests

- Keep PRs small and focused. Separate refactors from behaviour changes.
- Match the existing conventional-commits style for commit subjects:
  `fix(scope): ...`, `feat(scope): ...`, `docs: ...`, `ci: ...`.
- Add or update tests for behaviour changes. Prefer ephemeral fixtures
  (`t.TempDir()` + inline strings) over committed `testdata/` files
  unless a fixture is needed by multiple tests.
- Update `README.md` when adding or changing a user-facing flag, profile,
  ecosystem, or output field.

## Adding an exposure catalog

New catalogs land under `threat_intel/`. Before submitting:

- Validate against the published schema. A quick check, using the
  Python `jsonschema` package (`pip install jsonschema`):

  ```sh
  python3 -c "import json, jsonschema; \
    jsonschema.validate(json.load(open('threat_intel/your-catalog.json')), \
      json.load(open('docs/schema/v0.1.0/exposure-catalog.schema.json')))"
  ```

- Include a `_comment` field at the catalog root with the methodology
  and source for the entries. Keep this on existing catalogs when
  editing.
- Use a documented severity value (`critical` is the only one used by
  shipped catalogs today; if you introduce a new value, justify it in
  the PR description).
- Include `source` on each entry pointing at the public advisory or
  research writeup that backs it.

Catalogs can also be generated offline from OSV data with
`tools/osvcatalog`; see [`threat_intel/README.md`](threat_intel/README.md).

## Schema changes

Any change to `docs/schema/v0.1.0/*.json` or the wire format that breaks
existing consumers is a breaking change. Land it as a new version
directory (`docs/schema/v0.2.0/`) and bump `model.SchemaVersion`
together; do not edit a published schema in place.

## Security issues

Do not file public issues for vulnerabilities. See `SECURITY.md`.

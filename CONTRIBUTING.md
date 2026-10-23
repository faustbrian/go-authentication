# Contributing

## Before Editing

1. Read [`AGENTS.md`](AGENTS.md) and the affected package's docs.
2. Run the focused Go tests for the affected package.
3. Identify owned dependencies and reverse dependants in `modules.json`.
4. Preserve unrelated work and generated/corpus provenance.

## Changes

Keep commits focused and conventional. Update every affected changelog with
the behavior and migration impact. Public API changes require compatibility
evidence and documentation. Specification behavior requires a decision record,
fixture coverage, and interoperability evidence.

New direct dependencies and dependency updates must follow the
[dependency governance policy](AGENTS.md#dependencies-and-supply-chain). Package-local
update bots are forbidden; the root policy owns every module and action update.

Specification-backed changes must follow the
[specification governance contract](AGENTS.md#design), update
the affected stable decision entries, and complete the Specification Decisions
section of the pull request template. An unresolved interpretation or stale
source pin is release-blocking; peer behavior cannot silently select policy.
The authoritative registers are maintained for the
[root module](docs/specification-decisions.md),
[JWT module](jwt/docs/specification-decisions.md), and
[OIDC module](oidc/docs/specification-decisions.md).

Selected full and release mutation gates must finish with zero surviving viable
mutants; mutation is not a prerequisite for ordinary edits or pull requests.

Do not add package-local workflows, permanent replacements, machine-specific
paths, bypass flags, broad mutation exclusions, or aggregate quality metrics
that hide a failing package.

Ordinary verification installs the exact published `golib` release declared by
`.golib.yaml`, without building it from source. CI verifies that release using
the immutable shared workflow and tooling source. The explicit manual root
qualification job remains a separate source-built full-contract diagnostic.

## Verification

Use Go 1.27.2 from this standalone repository; no sibling checkout or ecosystem
goal ledger is required. Run deterministic tests, including fuzz seeds, then an
explicit active smoke for an affected JWT parser:

```bash
GOWORK=off go test ./...
(cd jwt && GOWORK=off go test . -run '^$' -fuzz '^FuzzInspectCompactJWT$' -fuzztime=2s -timeout=2m)
```

Run affected nested modules directly with `GOWORK=off go test ./...` from their
directory. Preserve the intentional compatibility adapter bindings. Ordinary
repository routes with the published CLI are:

```bash
make check
make ci
```

These bounded routes cover all four catalog modules, the unchanged pinned RFC
vector identity/digest guard, and two selected JWT shutdown race tests. The
catalog requires no external services; OIDC retains its `integration` test tag
and configured-provider tests retain their skip behavior. Base-free local checks
run fuzz seeds/corpus, not active campaigns; changed-source CI selects bounded
active smoke for affected targets. The provider interoperability campaign remains
an explicit full operation with its existing container prerequisites.

Optional focused mutation and explicit full/API/specification/release routes:

```bash
golib mutation --module . --package basic
make check-full
golib api check
golib specification check --online
golib release dry-run --module .
```

`check-full` retains the original coverage, mutation, fuzz, benchmarks,
conformance and interoperability campaigns. Ordinary specification validation is
offline; online authority refresh is explicit. Release rehearsals are available
locally, not only in CI. Report unavailable or failing commands; partial results
are not release-ready.

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.

## Source Documentation

Install the checksum-pinned public verifier declared in `.golib.yaml`.
`make source-docs-check` validates objective Go comment, marker, link and
generated-producer structure; `make check`, `make check-full` and `make ci`
require it before their existing checks. Shared CI runs the same strict
contract and includes its result in Required. This is structural enforcement,
not a substitute for source-truth review or behavioral verification.

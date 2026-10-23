# Source documentation audit

[Documentation index](README.md)

This is a dated snapshot of the root v2 source. Root v3 later removed the
`authhttp` and `authlog` facades, the `authotel` module and the query
credential sources; package and module counts below describe v2.

## Pre-edit contract and ownership

Base `86eaee2108308839ba53aa1b1d09d99e856054cc`; clean detached main-source worktree.
This worker owns Tier A comments/docs only. Preserve the unrelated dirty original
checkout and other identity-platform worktrees. No runtime/dependency/fixture,
release, policy or specification-expectation repair is included.

Outcome: useful truthful authentication, extraction, identity/admission, callback,
cryptography/key-resolver and cache/remote lifecycle contracts across every source.
Direct consumers include composed authenticators, HTTP/logging/telemetry adapters,
published-v1 nested modules and cataloged Authorization, HTTP Middleware, Queue
Control Plane and Service integrations. Named risks: credential disclosure or
unsupported constant-time claims; malformed-header ambiguity; mutable provider
state and callback cancellation; copied versus borrowed principals; refresh retries,
cache freshness/rotation and shutdown; root-v2 versus intentionally frozen-v1
optional module bindings; unsupported protocol completeness assertions.

## Reproducible full tracked-source inventory

Use `git ls-files "*.go"`, `modules.json`, `packages.json` and native
`source-docs inventory/check --json`. Fresh inventory has 95 tracked Go files,
five modules and thirteen packages; 105 exported-comment omissions are structural
input, not a prose-quality score. No previous source-audit file exists.

- `.`: `composite.go`, `composite_test.go`, `contracts.go`, `contracts_internal_test.go`, `contracts_test.go`, `credential.go`, `credential_test.go`, `example_test.go`, `instrumentation.go`, `instrumentation_test.go`, `principal.go`, `principal_admission_additional_test.go`, `principal_admission_composition_test.go`, `principal_admission_test.go`, `principal_fuzz_test.go`, `principal_options.go`, `principal_test.go`, `static_admission_composition_test.go`.
- `adapters/http`: `challenge.go`, `challenge_test.go`, `example_test.go`, `extractor.go`, `extractor_benchmark_test.go`, `extractor_fuzz_test.go`, `extractor_test.go`, `interoperability_test.go`, `invariants_test.go`, `middleware.go`, `middleware_test.go`.
- `adapters/otel`: `authotel.go`, `authotel_test.go`, `benchmark_test.go`, `example_test.go`, `hardening_test.go`.
- `adapters/slog`: `authlog.go`, `authlog_test.go`, `example_test.go`, `privacy_test.go`.
- `apikey`: `authenticator.go`, `authenticator_test.go`, `example_test.go`, `static.go`, `static_admission_test.go`, `static_benchmark_test.go`, `static_test.go`.
- `authhttp`: `authhttp.go`, `compatibility_test.go`.
- `authlog`: `authlog.go`, `compatibility_test.go`.
- `authotel`: `authotel.go`, `authotel_test.go`, `benchmark_test.go`, `example_test.go`, `hardening_test.go`.
- `authtest`: `authtest.go`, `authtest_test.go`.
- `basic`: `example_test.go`, `options.go`, `options_internal_test.go`, `static.go`, `static_admission_test.go`, `static_benchmark_test.go`, `static_test.go`.
- `bearer`: `authenticator.go`, `authenticator_test.go`, `example_test.go`, `static.go`, `static_benchmark_test.go`.
- `jwt`: `example_test.go`, `fuzz_test.go`, `hardening_internal_test.go`, `interoperability_test.go`, `jwk_member_names_test.go`, `remote.go`, `remote_internal_test.go`, `remote_retry_test.go`, `remote_test.go`, `validator.go`, `validator_benchmark_test.go`, `validator_internal_test.go`, `validator_test.go`.
- `oidc`: `example_test.go`, `fuzz_test.go`, `interoperability_test.go`, `keycloak_interoperability_test.go`, `mutation_regression_internal_test.go`, `remote.go`, `remote_concurrency_test.go`, `remote_internal_test.go`, `remote_test.go`, `upstream_keyset_test.go`, `validator.go`, `validator_benchmark_test.go`, `validator_internal_test.go`, `validator_test.go`.

## Missing documentation versus investigation questions

Repair exported interface/field contracts and package entrypoint/ownership docs.
Audit all private mechanisms and every test/helper/fuzz/benchmark/example against
actual branches before documenting rationale. Investigate which errors are safe
versus inspectable, whether context cancellation interrupts work, nil/zero/default
behavior, immutable snapshots, option/provider validation, allowed algorithms and
claim/credential bounds. Separate unsupported or unexplained existing behavior
from missing comments; do not invent security/concurrency guarantees.

## Variants, immutable inputs and selected proof

Root is v2; JWT/OIDC and both OTel modules deliberately import published root
v1.2.2, not this local v2 source. Preserve these exact module/dependency and API
baselines. authhttp/authlog retain deprecated forwarding surfaces; authotel retains
a separate deprecated nested module. OIDC has an integration-tagged provider test.
No generated Go or generator directives were found. Inventory all deprecation,
analyzer/debt markers and source pins; preserve normative expected requirements.

All five configured native API baselines use apidiff. Comments do not require
rewriting frozen signature files or go-doc snapshots. After explicit coordinator
Go-slot grant: pinned1.27.2 formatting and all95 AST/signature/literal/directive
and significant-token preservation; parsed/HTML comments and thirteen native
package renders; configured/native docs selectors plus existing Examples across
all five modules. No live providers, services, race/fuzz/mutation/conformance or
performance campaign for unchanged executable contracts. Native offline source/
spec checks, affected local links, protected-input identity, pinned changed-added/
staged secrets and ordinary complete Tier A final-diff review precede explicit
Intent/ACK safe-wrapper commit. Three owned caches/helpers/renders are disposable
and removed on success/failure; coordinator owns remote/CI/goal completion.

## Source-grounded coverage and observed limitations

All 25 production sources and 70 test/example/fuzz/benchmark/helper files were
reviewed by their actual input/ownership families, not by comment counts. Twelve
Examples, nineteen fuzz targets and eighteen benchmark entrypoints remain
executable-equivalent. Fuzz headers distinguish ignored outcomes from real
classification/formatting assertions; benchmarks distinguish setup-excluded
validation from discovery IO, cached-key misses and environment-sensitive heap
observations. The integration-tagged Keycloak fixture stays unchanged and is
not live-provider qualification. No debt/generator markers exist; all thirty-
seven deprecations retain their required paragraph syntax.

Root v2 principals perform finite admission before cloning retained data;
strings are not normalized or confidentiality-classified. Credential values
retain raw strings and expose sensitive accessors despite fixed formatting.
Failures hide cause text by default, not through explicit Unwrap/Kind/challenge
inspection. Composite copies routing storage but borrows providers; only
rejected attempts fall through and provider/context cooperation is not forced.
Telemetry isolates selected callbacks' panics, not latency/authenticator panic;
owned adapters project labels but generic open string types are not screened.
HTTP extraction has per-value limits after complete query/cookie parsing, not
an aggregate request-allocation bound. Middleware is authentication-only and
requires a valid challenge before a 401; provider/body/next-handler lifecycle
is external. Static HMAC digest scans are not whole-call constant-time proof,
secret erasure or retained-history/version fencing. Scripted authtest.Kind
callbacks run under the fixture lock and must not reenter or block; this is an
existing trusted-fixture limitation, not general hostile-provider isolation.

JWT/OIDC import published root v1.2.2 with 128-claim/depth8/collection256 limits,
not the local v2 aggregate/string/node admission. Their trusted clocks/providers
can panic/block and typed-nil Clock is not detected. JWT provider-set JSON
serialization precedes key-count admission. JWT NumericDate profile is integral;
OIDC preserves rational fractions, truncating sub-nanosecond values. OIDC
front-channel bindings require supplied values and supported hash suffixes;
empty values skip checks, EdDSA supplied bindings refuse, binding strings have
no independent size cap, and optional nonce policy is not automatic replay
protection. OIDC refresh is synchronous, with bounded participants, freshness/
cooldown, retired-fingerprint history and no public Close/Shutdown. Its stale
refresh failure does not extend last-good trust. JWT remote cache retains keys
under fail-stale policy and owns explicit sticky-stop/drain/shutdown lifecycle.

One disposable non-network observation used the actual local JWT module with
an always-unavailable synthetic provider: an ordinary object and malformed
trailing suffix each invoked Provider once; a second valid JSON value invoked
it zero times. All returned errors. This proves the existing preflight/provider-
order discrepancy caused by treating every trailing decoder error as EOF, not
final authentication acceptance, conformance or a supported wire interpretation.
Desired strict JSON expectations and frozen authorities remain unchanged. No
runtime fix or wider malformed-token campaign ran.

Actual imported JWX v3.3.0 cache delegates Shutdown to httprc v3.0.6
ShutdownContext, which cancels then selects caller cancellation versus join.
NewRemote's failed-registration path passes its possibly expired init context
and discards the shutdown result/owner: cancellation may be requested without
completed joining before constructor refusal. This is a source-visible failure-
path join gap, not a proved permanent leak. No live/network failure probe ran.
The published root v1.2.2 constructor/copy source was also inspected; its
absence of v2 aggregate/string admission remains an intentional frozen binding.

The preflight ordering and constructor failure-join gaps need separately scoped
behavioral decisions/repairs; no expectation was rewritten to endorse them.
Other unresolved rationale: per-generation explicit-refresh error publication
uses one mutable refreshErr rather than per-generation result storage; no claim
of a reproduced race is made. Custom provider blocking/timing/privacy and
network egress are application decisions, not inferred package guarantees.

## Native evidence and final review

Pinned Go1.27.2 checked formatting and exact comment-free AST/signatures,
literals and directives across all95 files. Raw token difference is one optional
implicit semicolon before the closing brace of canonical multiline authtest.Call;
normalizing only that grammar-optional token gives exact identity. All458 comment
groups parsed/rendered and all13 catalog packages rendered via native go doc.
Five configured native apidiff gates passed without rewriting signature baselines.
Native docs selectors passed four nested Examples (including JWT's declared
Makefile recipe) and native links had zero errors/two declared exclusions. Root's
native docs operation is links-only, so the eight root Examples were separately
executed with `go test ./... -run '^Example' -count=1 -timeout=2m`; all twelve
existing Examples passed. No integration tag/live provider or broad campaign ran.

Final imported-source review added the precise NewRemote failure-join caveat;
affected jwt/remote.go raw tokens/AST/literals/directives are exact, twenty
comment groups rendered, and affected JWT GoDoc refreshed. The twelve unaffected
package renders and four nested Examples retain their initial session result.
Ordinary final review corrected FormatChallenge's decision reference to existing
AUTH-DEC-007; this plain-text identity correction receives fresh structural/
register-target inspection, reusing unchanged native rendering structure rather
than presenting an unchanged runtime campaign as new evidence.

Ninety-one tracked API/dependency/catalog/specification/verification/dated threat-
model/register inputs remain unchanged. Native source checker reports zero
structural findings; offline specification checker accepts three modules and
forty-eight existing decisions. Two preparatory helper failures (stdin EOF and
metadata-only module lookup without downloaded Dir) occurred before applicable
proof commands, cleaned automatically, and were resolved. The provider-order
observation was reused, not rerun. All exact Go build/module/temp caches, helper,
probe and rendered output sessions were removed on normal/failure exits with
absence verified. Current source/prose receive one complete ordinary TierA review;
secrets/staging/Intent commit evidence is recorded separately from parent-owned
CI/main/publication. No normative expectation or policy was weakened.

Affected local Markdown targets/decision references and staged whitespace are
valid. Pinned Gitleaks v8.30.1 with retained native policy found zero findings
on all48 staged added/new-file inputs; no findings, policy or ignore entries
were suppressed. Its owned private output/report/snapshot was removed. The
explicit-path Intent commit and parent-owned delivery remain separate states.

## Objective Enforcement

The checksum-pinned public Tools v2.4.0 verifier now supplies
`make source-docs-check` as a prerequisite of the existing local and CI Make
routes. Ordinary shared CI selects strict source-documentation checking and
requires its result. Native prerequisites, operation budgets, security and
release controls are retained. Hosted exact-head evidence is recorded by the
coordination ledger; configuration alone does not establish green delivery.

Continue with [Exported API map](api.md).

# Security test matrices

## Protocol and interoperability

| Surface | Positive vectors | Negative vectors |
| --- | --- | --- |
| HTTP | RFC 7617 Basic, RFC 6750 Bearer, explicit API-key sources | duplicates, mixed sources, controls, oversize fields, malformed encodings |
| Challenge | deterministic schemes and escaped parameters | controls, invalid tokens, parameter count and size limits |
| JWT | RFC 7520 JWK, valid compact JWS, rotation | algorithm/key mismatch, ambiguous IDs, invalid metadata, critical headers, claim/date bounds |
| OIDC | OIDC Core claim set, discovery, known-key outage | issuer query/redirect, unknown keys, invalid dates/party/nonce, oversized responses |
| Static keys | current/previous overlap and atomic replacement | revoked, unknown, duplicate, empty, oversized sets |

The exact static data is recorded in [vectors.md](vectors.md). Executable
sources are `adapters/http/interoperability_test.go`,
`jwt/interoperability_test.go`, and `oidc/interoperability_test.go`.

## Failure injection and lifecycle

| Failure | Expected behavior | Evidence |
| --- | --- | --- |
| Issuer timeout or 5xx | known OIDC key remains usable; unknown key is unavailable | `oidc/remote_test.go` |
| Refresh stampede | one network owner, bounded cancellation-aware waiters | `oidc/remote_concurrency_test.go` |
| JWT shutdown during refresh | admitted work cancelled and drained before shutdown returns | `jwt/remote_test.go` |
| Shutdown deadline | returns context error without admitting more work | `jwt/remote_test.go` |
| Instrumenter failure | authentication result is unchanged | instrumentation and adapter tests |
| Callback rejection/unavailability | stable typed failure, no wrapped secret rendered | root and adapter tests |

## Ordinary and full verification

| Gate | Command |
| --- | --- |
| Bounded local checks, deterministic tests and fuzz seeds | `make check` |
| Pinned RFC vector identity/digests and two focused protocol tests | `make conformance` (also required by ordinary Make and CI) |
| Two selected JWT shutdown race tests | `make check` |
| Explicit active JWT parser smoke | `(cd jwt && GOWORK=off go test . -run '^$' -fuzz '^FuzzInspectCompactJWT$' -fuzztime=2s -timeout=2m)` |
| Repository/cohesion checks plus bounded local verification | `make ci` |
| Original coverage, full fuzz, mutation, benchmarks, conformance and interoperability | `make check-full` |
| API compatibility | `golib api check` |
| Online specification authority | `golib specification check --online` |
| Reproducible archive | build twice and compare SHA-256 output |

Base-free local checks do not run active fuzz campaigns; changed-source CI
selects bounded active smoke for affected targets. Keep external-provider and
container prerequisites for the explicit interoperability route. Release
qualification remains available locally through `golib release dry-run`.

Benchmarks in the repository cover static authentication, extraction, JWT,
and OIDC validation. They are regression signals rather than timing-side-
channel proofs; constant-time static comparison is established by fixed-size
digests, `subtle.ConstantTimeCompare`, and bounded full scans.

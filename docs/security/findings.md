# Security audit findings

The audit reviewed protocol parsing, secret handling, concurrency, remote key
lifecycles, dependency direction, interoperability, and resource bounds. Each
finding below includes its reproducer and final disposition.

| ID | Severity | Evidence and reproduction | Disposition |
| --- | --- | --- | --- |
| AUTH-001 | High | Concurrent unknown OIDC key IDs could queue behind an issuer fetch without a waiter bound; reproduced in `oidc/remote_concurrency_test.go`. | Fixed with one refresh owner, bounded waiters, cancellation-aware waits, cooldown, and min/max freshness. |
| AUTH-002 | High | `jwt.Remote.Close` could race an admitted refresh and deadlock shutdown; reproduced by deadline and state tests in `jwt/remote_test.go` and `jwt/remote_internal_test.go`. | Fixed by owning, cancelling, and draining admitted operations before upstream shutdown. |
| AUTH-003 | High | A JWK selected by ID could carry metadata or key material inconsistent with the configured algorithm; reproduced in JWT and OIDC validator tests. | Fixed with key-family, curve, validation, `use`, and `key_ops` enforcement. |
| AUTH-004 | Medium | OIDC expiry used upstream timing while other dates used local policy, producing inconsistent skew; reproduced by numeric-date tests. | Fixed by enforcing `exp`, `nbf`, `iat`, and `auth_time` once through the configured clock and skew. |
| AUTH-005 | Medium | Basic user/password inputs containing control bytes were accepted; reproduced by extractor and static-authenticator tests. | Fixed according to RFC 7617 before storage or authentication. |
| AUTH-006 | Medium | Challenge parameters lacked explicit count/size bounds and accepted control bytes; reproduced in `adapters/http/challenge_test.go`. | Fixed with exported limits and strict quoted-text validation. |
| AUTH-007 | Medium | An OIDC issuer URL could include a query component; reproduced in OIDC configuration tests. | Fixed by rejecting issuer queries and fragments per OIDC Discovery. |
| AUTH-008 | Medium | Explicit query credential sources can expose secrets to infrastructure before extraction. The library has no URL-writing API, so no source-level output leak was reproduced. | Residual deployment risk documented; query constructors retained for compatibility and deprecated for new designs. |
| AUTH-009 | Low | Hostile header and challenge fields were not directly fuzzed. | Fixed with bounded fuzz targets for complete header sets and challenge formatting. |

## Published-version and disclosure disposition

The fixes for AUTH-001 through AUTH-007 are already present in the first
standalone published releases. The root `v1.0.0`, `jwt/v1.0.0` and
`oidc/v1.0.0` tags all resolve to commit
`9f3aa6f181833ff4a4ca474d868711d1dd2b9122`, whose source, regression tests and
finding record include those controls. They must not be presented as fixes
introduced by root v2 or as vulnerabilities affecting every earlier major.

| Finding | Owned module | Earliest verified published fixed release |
| --- | --- | --- |
| AUTH-001 | `github.com/faustbrian/go-authentication/oidc` | `oidc/v1.0.0` |
| AUTH-002 | `github.com/faustbrian/go-authentication/jwt` | `jwt/v1.0.0` |
| AUTH-003 | JWT and OIDC optional modules | `jwt/v1.0.0` and `oidc/v1.0.0` |
| AUTH-004 | OIDC optional module | `oidc/v1.0.0` |
| AUTH-005 | Root Basic authentication and HTTP extraction | `v1.0.0` |
| AUTH-006 | Root challenge contract and HTTP formatting | `v1.0.0` |
| AUTH-007 | OIDC optional module | `oidc/v1.0.0` |

No affected tagged standalone release has been established for these findings;
record them as pre-publication remediation, not an invented affected range.
The initial repository commit already marks them fixed, so this record does
not establish whether a vulnerable predecessor was ever distributed under a
historical monorepo or pseudo-version identity. The absence of an existing
advisory is not evidence that no exposure occurred. The maintainer must reopen
the version assessment if such a published predecessor is identified and
prepare a private advisory with its precise affected module and versions.

Later JWT lifecycle improvements and dependency remediation retain their own
changelog entries; they are not evidence that AUTH-002 or AUTH-003 persisted
until those releases. Root v2 admission limits likewise do not retroactively
apply to the root v1 or optional-module APIs.

## Accepted deployment residual: AUTH-008

The maintainer, `faustbrian`, owns the explicit query-source API and its
deprecation guidance. The deploying application operator owns credential
transport, browser-facing URLs, reverse proxies, access logs, and retention.
The retained option supports existing integrations; it is not a safe default
or a recommendation for new designs. No library URL-writing API or reproduced
source-level output leak is implicated by this finding.

Mitigation is to migrate new and existing integrations to authorization or
dedicated credential headers and prevent credential capture at upstream
logging boundaries, as described in the [adoption checklist](../adoption.md).
Header migration does not erase previously retained URL credentials; operators
must address existing exposure and credential rotation within their deployment.

Review this acceptance whenever query-source defaults, URL construction,
credential transport, logging or retention policy changes, or new evidence
shows source-level disclosure. The maintainer reviews API changes; the
deploying operator reviews deployment changes and any recorded exposure.

## Rejected boundary findings

- Authorization is intentionally absent: the authenticated principal is an
  input to a separate policy layer, not evidence that an action is allowed.
- The root module permits only the dependency-free `clock` capability
  module. Optional modules do not import `service`, `http-client`, or
  `authorization`; the executable boundary check prevents this repository
  from closing a dependency cycle.
- OIDC owns no background goroutine. JWT remote resources expose an explicit,
  idempotent, deadline-aware `Close` and reject new work after closing begins.

No identified source-level security blocker remains. Release readiness still
depends on the local gates listed in [test-matrices.md](test-matrices.md).

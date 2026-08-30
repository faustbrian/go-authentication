# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
this project follows Semantic Versioning.

## [Unreleased]

### Changed

- Replace copied repository tooling with the pinned `go-library-tools` v1.0.13
  contract while retaining package-owned policy and verification evidence.

### Documentation

- Replace archived monorepo links with a package-owned documentation index.
- Make the current [authentication specification decisions](docs/specification-decisions.md)
  machine-auditable and preserve their content identities below.
- Treat recorded decision digests and public conformance test identifiers as
  non-secret specification metadata during repository scanning.
- AUTH-DEC-011 sha256:be33f5111184dec4c31bdeac3760ee2ef0fcdd730a677f55479e7ee8f66ad659
- AUTH-DEC-012 sha256:9135676640d9c0df84a1b676985d9f5c2512998304591b8809092b50ce0d7884
- AUTH-DEC-001 sha256:dbf293fd525d952dfe51ac1af7a43325429fa00dfe6d34e2cdc45069830330f5
- AUTH-DEC-002 sha256:5d9b14d24d6ac9ea1f84b43d5d745454b53e5271fee035aa909d1d9a2342d5fe
- AUTH-DEC-002 sha256:15e8ade498da812548bf36deb3ab0b77d5fae91462036bc36e27aaa39fb4f273
- AUTH-DEC-003 sha256:81ffead77cfa54913477444f24798f9b632beb94057e578ec1f266b020c6a7c1
- AUTH-DEC-003 sha256:10e348b7b49b28fb53f35f0072cbda5ff08156f871c854fcb7e0f62b70f0ed9e
- AUTH-DEC-004 sha256:86762f7d564203e9714e51b867aa8ec4ebc913d0ca704e716a409e56b2537722
- AUTH-DEC-004 sha256:06998d20abf14867af6c7195a88b8adadc4a66dda00e1990172180c5c71a61a6
- AUTH-DEC-005 sha256:b8d53a0e3c0980892e5b161e2e5b2534f635d250e4310757d11d78ff08b773c4
- AUTH-DEC-006 sha256:e18d639138c2828e3b8240a6bf80c5437b04d630da12cc3e419d476ab35b88e7
- AUTH-DEC-007 sha256:f8b3f8e8393811a2c3ce06988b92f81252babeede518c6836afaac7a3de89326
- AUTH-DEC-007 sha256:e9a921116a9efa033845aff4eb3e931303ad4f1380b190338c730245ea8860d6
- AUTH-DEC-008 sha256:b4f02becb2f6f0f2d098c8d24fe750048bf87f8d2aefc8c680745c0d240c812a
- AUTH-DEC-009 sha256:0104da4c0dca68fb7146d17f5d70077fe34edaf919feef29b718252edb65ee37
- AUTH-DEC-010 sha256:4a94dc00885603ca190f6e2eda39a98d09511ff7417bb3de9cb131774398d60f

## [1.0.0] - 2026-08-25

### Fixed

- Run OIDC Keycloak interoperability through the repository-owned standalone
  script instead of a removed monorepo-relative path.

### Changed

- Upgrade JWT cryptographic dependencies to their current secure releases.

- Exclude intentional nested modules from root local-proxy archives so local,
  bootstrap, CI, and public module checksums describe the same source
  boundary.

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

### Documentation

- Replace obsolete standalone-repository links and workflow claims with
  monorepo-canonical targets and current release guidance.

- Link the package README to package-owned documentation.

### Security

- Protect static Basic and API-key credentials with random per-authenticator
  HMAC-SHA-256 keys instead of reusable unkeyed secret digests.
- Enforce and prove inclusive credential, principal, challenge, collection, and
  static-entry bounds at their exact limits; reject forged result states and
  provider method mismatches without weakening fail-closed behavior.

### Fixed

- Bind package-owned composition and static-secret lifecycle decisions to the
  authoritative RFC authentication and credential-security constraints.
- Return authentication unavailability instead of emitting a non-compliant
  `401 Unauthorized` response when no valid `WWW-Authenticate` challenge is
  available.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-authentication` identity while preserving its documented API and behavior.
- Replace obsolete owned-module pseudo-version pins with the monorepo's local
  `v0.0.0` source-proxy coordinates; release tooling continues to emit exact
  `v1.0.0` dependency versions.
- Link specification provenance directly to the canonical decision register so
  conformance rationale and executable evidence remain discoverable.
- Require owned sibling modules at local `v0.0.0`; clean external consumers
  pin each module to an exact main pseudo-version.

- Add explicit pipe-compatible bearer extraction for legacy opaque-token
  contracts while retaining strict RFC 6750 syntax by default.
- Preserve `apikey.Static` comparability while retaining per-authenticator
  keyed credential digests.
- Execute API compatibility tooling against the isolated module graph so owned
  dependency source changes cannot conflict with release checksums.
- Refresh owned-module checksums against the final consolidated archives.
- Normalized standalone module metadata against the canonical owned dependency
  graph, including complete checksums for clean consumer resolution.
- Use the repository-pinned current `apidiff` revision for root and optional
  authentication-module compatibility checks.

### Added

- An auditable specification decision register for Basic, bearer, API-key,
  challenge, credential-source, middleware, composition, and rotation policy.
- Constant-work static bearer authentication with bounded overlapping tokens
  and atomic whole-set replacement for credential rotation and revocation.
- Immutable bounded principals, typed redacted credentials, explicit anonymous
  results, stable failures, challenges, context helpers, and deterministic
  authenticator composition.
- Constant-time static Basic and API-key authentication, atomic API-key
  rotation, and callback bearer and API-key adapters.
- Strict opt-in HTTP header, query, and cookie extraction with fail-closed
  authentication-only middleware.
- Optional JWT/JWK and OIDC modules with bounded remote key handling, strict
  algorithm and claim validation, rotation, stale-key behavior, and owned
  resource lifecycle.
- Secret-safe `slog` and optional OpenTelemetry instrumentation adapters.
- Deterministic test fixtures, runnable examples, fuzz targets, race tests,
  benchmarks, exact statement coverage gates, API compatibility checks, and
  reproducible release automation.
- Security audit artifacts covering the threat model, findings, protocol and
  failure-injection matrices, authoritative vectors, and secure adoption.

### Changed

- OIDC remote refresh now has bounded cancellation-aware waiters, conditional
  requests, bounded freshness, failure cooldown, and consistent numeric-date
  skew enforcement.
- JWT remote shutdown now owns, cancels, and drains admitted operations.
- JWT and OIDC reject algorithm/key-family and JWK metadata mismatches.
- Basic credentials and HTTP challenges reject control bytes, and challenges
  enforce explicit parameter and field bounds.
- Query credential constructors are deprecated for new designs.

[Unreleased]: https://github.com/faustbrian/go-authentication/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/faustbrian/go-authentication/releases/tag/v1.0.0

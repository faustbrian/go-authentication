# Changelog

All notable changes to this module are documented here.

## Unreleased

### Changed

- Publish schema-v2 cohesion metadata for JWT validation and remote JWK cache
  ownership, with an immutable Golib ecosystem-index entry point.

### Documentation

- Move detailed module guidance behind a concise README and documentation index.
- Use human-oriented section names and package-owned documentation links.
- Make the current [JWT specification decisions](docs/specification-decisions.md)
  machine-auditable and preserve their content identities below.
- JWT-DEC-014 sha256:0e45ac787af263eb7b848968a9ed01c1f03ad5a7a1b5ce5383c5b0defdbbbf49
- JWT-DEC-015 sha256:be343023ac0ba642b4d7775a190bb8e31489f545db7ee0395c8ff94f5651c9b5
- JWT-DEC-001 sha256:c34ccac9c82afd4da8c871bee6fe821ccff46c8c9060c7f41fc5e9bd3e196d0e
- JWT-DEC-002 sha256:6c294c0a2a0b8bd8b9161252fd65db343376a0f7f3132b6b19af8948599ea2a5
- JWT-DEC-002 sha256:a628f9aed40bc1de1261c54fd349c6166e71bc1112e350010cd920eef1ed16bb
- JWT-DEC-003 sha256:960a82f9867e893c1836832ab451920ef744abed1b98f7ade602004afc0433ca
- JWT-DEC-003 sha256:2f1485ce6dc9f018d99605a8748c711f465d40e775b582d7809f75e00a54856b
- JWT-DEC-003 sha256:56a3c44633d83c6fc83fa27e1c7ba4da3243e50152d96801aa11c4137e472170
- JWT-DEC-004 sha256:0ac983e3acb7fd3cb5d1422d02c798362106ddd9b75827714dae42f5988ba81d
- JWT-DEC-005 sha256:138331f4ce5cbab2cfde49f71d6c3fd540de840a7d4a277037b44bb3179adc5c
- JWT-DEC-005 sha256:5ec36b6e11978d45f1f01028c6db35b084aae3fea4ae18d3cf2f64a45d388d6f
- JWT-DEC-005 sha256:bde6c358f9d04236bda3385afc90b3397cbe7da8858248e2d0239af1c7e13bb3
- JWT-DEC-005 sha256:f6914acc21328190b95498f72e60fd12a9ff21a6973c513f9a4eab290cf3536e
- JWT-DEC-006 sha256:d5c41ddbb6ac37f114e997d2ef9d4553dda87a4f1cb3dfde03aa6d55f1bddaee
- JWT-DEC-007 sha256:6b9626f8957a1655bf42fe94dd71971b74fdd12571ba64dee57363e9f1dbc8d2
- JWT-DEC-007 sha256:1e7d38dc50c0551b9cf20942cdc9e32b5bc99b1ca497b62fd9efa8a33fd2cd46
- JWT-DEC-008 sha256:98b9d6b25d9f48a94a884fe358947c5a80b1b1b03ad16d0ca3e3a7ec9a12f295
- JWT-DEC-009 sha256:ab5495c596db42bf31c283a6fbb43fa2bfbafb77a5e1574bc4f8a0c47c00f3f9
- JWT-DEC-010 sha256:01dd4afda845e628c1323922793cfc05adf8ea1ccb73f0cd89a3b364a400ac6c
- JWT-DEC-011 sha256:de8687c3208a013ccf524091f08a6b87491c9982c4457da7e5de4cedddae7ce4
- JWT-DEC-012 sha256:b1618ad8d71a7d46b12e2df0c8d52b001baa3abbaf7c08de7ff2cf5f48abe48c
- JWT-DEC-013 sha256:e615831f9bf926e4ca9e65d51e1164f2b372ff5a042c678fd194b5368b00ef47

## 1.0.0 - 2026-08-25

### Security

- Use one clock instant for every claim check in a validation attempt, reject
  fractional and exponent NumericDate encodings that invite parser-dependent
  rounding, and preserve private JSON numbers losslessly instead of exposing
  rounded `float64` values.
- Require verification-only JWK operations, treat conflicting `max-age`
  directives as immediately stale, and keep remote work permanently rejected
  after close begins even when a close attempt is canceled.
- Make the default remote HTTP transport safe, reject typed-nil transports,
  and complete successful remote-cache initialization with exactly one bounded
  request.
- Preserve the last validated remote key set across hostile refresh responses,
  prove old-key eviction and outage recovery, and ensure unknown key IDs never
  trigger attacker-driven fetches.
- Require canonical unpadded base64url signatures and JSON-number NumericDate
  claims; add exact subject allowlists and custom required-claim policy, and
  reject configurations whose claim bound cannot hold every required claim.
- Reject build-tag-dependent ES256K so the published algorithm matrix remains
  completely executable under the module's canonical build.
- Keep safe standards error categories while replacing provider and transport
  causes with a stable redacted key-provider category.
- Route automatic JWKS refresh through the configured hardened client,
  serialize it with explicit refresh work, detach provider lifetime from the
  constructor context, honor freshness directives and response age, and avoid
  body-limit arithmetic overflow.
- Reject invalid UTF-8 in protected headers and claim sets instead of allowing
  JSON decoding to replace malformed bytes.
- Enforce algorithm-specific HMAC sizes, RSA modulus bounds, exact EC curves,
  public-only asymmetric verification keys, and reject token-provided key
  references, unpaired Unicode surrogates, and oversized JSON numbers.
- Bound remote JWK headers, bodies, key counts, initialization, and concurrent
  operations; reject redirects and compression; validate responses before
  caching; deep-copy returned sets; coalesce refreshes; and independently
  jitter refresh schedules across provider instances.

### Documentation

- Link the package README to package-owned documentation.

- Add the stable JWT, JOSE, JSON, remote-JWKS, cache, lifecycle, and diagnostic
  specification decision register with executable evidence links.
- Document strict claim and algorithm policy, local and remote key ownership,
  fail-stale refresh behavior, cancellation, close semantics, error redaction,
  adoption, migration, security tradeoffs, and compatibility.

### Interoperability

- Add full signed-payload and cache-header fuzz boundaries alongside the
  compact-token and remote-response fuzz targets.
- Add the RFC 7515 Appendix A.2 RS256 compact JWS and bidirectional
  golang-jwt interoperability for every shared HMAC, RSA, PSS, and ECDSA
  algorithm.
- Verify bidirectional HS256 compatibility with golang-jwt v5 in addition to
  the pinned RFC 7520 JWK vector and lestrrat-go/jwx implementation.

### Distribution

- Include the canonical MIT licence in the independently published module.

### Compatibility

- Added a pinned module export baseline so incompatible public API changes
  fail the canonical repository gate.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-authentication/jwt` identity while preserving its documented API and behavior.
- Refresh local `v0.0.0` owned-module checksums after dependency manifests and
  release notes were normalized; runtime behavior and public APIs are
  unchanged.
- Require owned sibling modules at local `v0.0.0`; clean external consumers
  pin each module to an exact main pseudo-version.

- Refresh owned-module checksums against the final consolidated archives.
- Normalized standalone module metadata against the canonical owned dependency
  graph, including complete checksums for clean consumer resolution.
- Refreshed the canonical authentication checksum after its test archive
  changed, preserving isolated module verification.
- Refreshed the canonical authentication checksum after its API compatibility
  baseline was normalized to the module boundary.

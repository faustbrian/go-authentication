# Compatibility

## Go and modules

The supported floor is Go 1.27.0. The repository contains independent modules:

| Module | Runtime dependency policy |
| --- | --- |
| root | Standard library and the explicit go-clock v1 contract |
| `/jwt` | JWX v3 and its owned HTTP resource cache |
| `/oidc` | coreos/go-oidc v3 and go-jose v4 |
| `/adapters/otel` | Preferred OpenTelemetry API adapter; SDK only in tests |
| `/authotel` | Deprecated compatible path retaining its original telemetry scope |

The public module floor remains Go 1.27.0; development and CI use patched
Go 1.27.2. Each optional module resolves its declared dependency graph
independently of the root module. Applications must be rebuilt with a
patched compiler to receive standard-library security fixes.

## API stability

Incompatible API changes require a new major release and must be
documented with migration guidance. At v1, exported identifiers and behavioral
contracts follow Semantic Versioning. Adding a new failure kind, credential
kind, algorithm requirement, default bound, or stricter parser behavior is a
user-visible change even if Go signatures remain compatible.

API baselines are maintained separately for the root and each optional module.
Generated interfaces from dependencies are not part of this project’s API.

The published root v2 release uses the `/v2` module/import suffix for its
narrower Principal and static-credential admission contract. Root v1 remains
published separately; optional modules retain their existing v1 nominal APIs
until their own major migration. The historical root API baseline is retained
alongside the separately generated v2 baseline.

The root `Instrumenter.Start` interface remains unchanged so existing
implementers compile. New integrations implement `BeginInstrumenter.Begin` and
use `NewInstrumentedWithBegin`. JWT `Remote.Close(ctx)` remains available and
delegates to the preferred `Remote.Shutdown(ctx)` lifecycle name.

Deprecated paths remain supported for the longer of 180 days and two
published stable minor releases of the old path after the replacement is
publicly consumable. Removal additionally requires migrated owned consumers,
clean external-consumer evidence, and an authorized next-major release.

## Protocol compatibility

Basic follows RFC 7617 extraction shape without negotiating a charset. Bearer
header grammar follows RFC 6750 `b64token` by default.
`authenticationhttp.WithBearerPipe` explicitly permits pipe-delimited opaque tokens for
legacy contracts without weakening the default. Challenges use safely quoted
and escaped auth parameters. Middleware never emits 401 without at least one
valid `WWW-Authenticate` challenge; missing challenge metadata maps to 503 as a
server-side inability to complete the protocol. JWT validation requires compact
signed JWS and strict registered claims. OIDC accepts asymmetric algorithms
explicitly listed in configuration and supported by the package.

The complete root-module interpretation contract is maintained in the
[specification decision register](specification-decisions.md). JWT and OIDC own
separate registers because they are independent modules and standards surfaces.

## Audited dependency lines

The July 2026 audit used Go 1.26.6 with JWX v3.1.1, `httprc` v3.0.5,
coreos/go-oidc v3.20.0, go-jose v4.1.4, and OpenTelemetry v1.44.0. This list
records that historical audit; module files and the immutable CI source
selection remain the authoritative current inputs.

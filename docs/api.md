# Exported API map

[Documentation index](README.md)

Every exported identifier has Go documentation and compiled examples are
checked in CI. Use `go doc` for signatures and contracts.

- Root: `Principal`, `PrincipalSpec`, credentials, results, `Failure`,
  `Challenge`, `Authenticator`, `Composite`, context helpers, and
  instrumentation.
- `basic`: immutable static Basic entries and authenticator.
- `bearer`: opaque-token validator interface, function adapter, bounds, and an
  atomically replaceable constant-work static token authenticator.
- `apikey`: callback validator, atomically replaceable static entries, and
  bounds.
- `adapters/http` (`authenticationhttp`): explicit sources, bearer compatibility options, extractor,
  challenge formatting, and middleware policies.
- `adapters/slog` (`authenticationslog`): standard `slog` instrumenter.
- `authtest`: deterministic principals, results, clock, scripted authenticator,
  HTTP fixture, and assertions.
- `jwt`: strict config, validator, provider adapters, and owned remote JWK
  lifecycle.
- `oidc`: discovery/static-key config, validator, and nonce interface.
- `adapters/otel`: OpenTelemetry provider config and instrumenter.

Instrumentation integrations implement `BeginInstrumenter.Begin` and use
`NewInstrumentedWithBegin` with a `clock.Clock`.

Challenge formatting is bounded by `MaxChallengeParameters`,
`MaxChallengeSchemeBytes`, `MaxChallengeNameBytes`, and
`MaxChallengeValueBytes`. OIDC remote policy is configured with
`MinRefreshInterval`, `MaxRefreshInterval`, and `MaxRefreshWaiters`; zero
values select safe defaults.

Credential sources read headers or explicitly named cookies only; root v3
removed query-string sources because credential-bearing URLs can be retained
outside this package.

`authenticationhttp.NewMiddleware` emits `401 Unauthorized` only when a failure-specific
or configured fallback challenge can populate `WWW-Authenticate`. If a
credential failure has no valid challenge, it returns the secret-safe
`503 Service Unavailable` response instead of producing an invalid bare 401.

The examples are discoverable with:

```sh
go test -run '^Example' ./...
(cd jwt && go test -run '^Example' ./...)
(cd oidc && go test -run '^Example' ./...)
(cd adapters/otel && go test -run '^Example' ./...)
```

See the [source documentation audit](source-documentation-audit.md) for full
module/variant coverage, actual ownership and existing limitations.

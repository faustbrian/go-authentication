# API reference

[Documentation index](README.md)

## Validator

`New(Config)` creates an immutable validator. Configuration requires one
issuer, one audience, a non-empty explicit algorithm allowlist, a non-nil
deterministic clock, and exactly one of `KeySet` or `Provider`.

`Config.Subjects` is an optional exact allowlist. A nil or empty list accepts
every non-empty subject. `Config.RequiredClaims` adds unique non-empty custom
claim names; the mandatory `iss`, `aud`, `sub`, `iat`, and `exp` names must not
be repeated. Both slices are defensively copied.

`MaxTokenBytes`, `MaxClaims`, `MaxClaimDepth`, and `MaxKeys` default to 16 KiB,
128 claims, depth 8, and 64 keys respectively. `Skew` defaults to zero and
cannot be negative. `MaxClaims` must accommodate the five mandatory claims plus
every custom required claim. `ScopeClaim` and `TenantClaim` default to `scope`
and `tenant` and must be distinct.

`ValidateBearer(context.Context, string)` validates one compact JWT and returns
an immutable `authentication.Principal`. `Authenticate` provides the same
behavior through the `authentication.Authenticator` contract and accepts only
`authentication.BearerCredential`. One configured-clock instant is used for
all temporal checks, and private JSON numbers remain exact `json.Number`
values in the principal. NumericDate claims accept integral JSON-number syntax
only; fractional and exponent forms are rejected.

`KeyProvider` exposes one context-aware `KeySet` operation. `KeyProviderFunc`
adapts a function to that contract. Provider sets are copied and revalidated
for each validation attempt. Their JSON serialization occurs before key-count
admission; provider objects must remain stable and bound that trusted work.
Strict JSON preflight requires the complete protected header and claims to end
at EOF before invoking the provider. Malformed trailing bytes fail rejected
without admitting provider work.

## Remote provider

`NewRemote` completes successful initialization with exactly one bounded fetch,
starts a provider-owned cache, and returns a `KeyProvider`. The caller must
call `Shutdown`.

Failed initialization cancels cache work and waits for cleanup with a fresh
timeout equal to `WithInitializationTimeout`. This can add one initialization
interval to a failed constructor call. If cleanup also fails, the returned
error joins the safe initial failure and cleanup failure; cancellation and
cleanup deadline causes remain inspectable with `errors.Is`. Custom transports
must cooperate with cancellation; a cleanup deadline reports incomplete
joining, not successful cleanup or forced callback termination.

- `WithHTTPClient` supplies the transport policy. The client is shallow-copied
  and then hardened with no redirects, no compression, exact-URL access, and
  configured response limits.
- `WithInsecureHTTP` permits plain HTTP for isolated development and tests.
- `WithRefreshBounds` sets positive minimum and maximum cache intervals.
- Refresh bounds default to one minute and one hour.
- `WithRefreshJitter` sets a fraction in `[0, 1)`; the default is 10 percent.
- `WithMaxJWKBodyBytes` defaults to 1 MiB.
- `WithMaxJWKHeaderBytes` defaults to 32 KiB aggregate header bytes.
- `WithMaxJWKKeys` defaults to 64 keys.
- `WithInitializationTimeout` defaults to 10 seconds.

At most 128 concurrent provider operations are admitted.

`KeySet` returns a deep copy of the current cached set. `Refresh` requests a
synchronous refresh; overlapping explicit refreshes retain the result of the
generation they joined, even if a later refresh finishes before they resume. All
automatic and explicit HTTP work is serialized. Caller cancellation stops
waiting. Once `Shutdown` begins, it permanently rejects new operations, cancels
admitted operations, joins them, and shuts down cache work. A canceled shutdown
may be retried. Concurrent callers use their own contexts; a waiter whose
context remains live continues any cleanup left incomplete by an earlier
canceled attempt.

## Remote deployment settings

`RemoteSettings` holds operator configuration for a remote-JWKS validator:
issuer, audience, JWK URL, algorithm names, skew, token and JWK body bounds,
initialization timeout, refresh bounds and `AllowInsecureHTTP`.
`RemoteSettings.Validate(SettingsPolicy)` refuses the first invalid field with
`authentication.ErrInvalidConfiguration`, naming the field but never its value
(JWT-DEC-016). Ceilings are five minutes of skew, 64 KiB tokens, 8 MiB JWK
bodies, a 30-second initialization timeout and a 24-hour maximum refresh.
`AllowInsecureHTTP` permits a plain-http JWK URL and HS* algorithms only when
`SettingsPolicy.PermitInsecure` is true; set it only for local or test
deployments. Validation does not build a validator: map the settings to
`NewRemote` options and `Config` yourself. See `ExampleRemoteSettings_Validate`.

## Errors

All failures support `errors.Is` and `errors.As` through
`authentication.Failure`. Credential shape, rejection, and provider failures
retain the authentication package categories. Safe JWX parse and validation
sentinels remain available for standards-backed decisions.
`ErrKeyProviderUnavailable` replaces raw provider and remote causes so the
error chain does not retain token, key, endpoint-query, or remote response
data.

Continue with [JWT validation technical guide](reference.md).

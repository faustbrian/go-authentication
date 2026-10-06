# Migration

## Root v2 import identity

The prepared root release is `v2.0.0`, not yet published. The latest public root
remains `v1.2.2`. After publication, change the root and its Basic, API-key,
bearer, HTTP, logging and test-package imports to
`github.com/faustbrian/go-authentication/v2` and the corresponding subpackage
paths. Root v1 and v2 Principal, Credential, Result and authenticator contracts
have distinct Go type identities; migrate each composed boundary together.

The independent `jwt`, `oidc`, `adapters/otel` and deprecated `authotel` modules
retain their released v1 paths, dependencies and APIs in this batch. They do
not acquire root v2 safeguards or type compatibility by sharing a repository.
Use their existing v1 route until a separately qualified compatible major is
public. In particular, do not replace a published consumer's exported v1
Authenticator field with a v2 type in a patch release.

## Static credential byte admission in the prepared root v2 release

Existing `basic.NewStatic` and `apikey.NewStatic` signatures remain available,
but their accepted input domain is narrower. Static Basic usernames and
passwords each have an inclusive 8 KiB raw-byte ceiling. Static API-key IDs have
an inclusive 256-byte ceiling, and keys an inclusive 8 KiB ceiling. Inventory
configured and incoming credential lengths before rollout; rotate values above
these defaults. These limits do not replace independent Principal admission.

Use `basic.NewStaticWithOptions` with `basic.WithMaxUsernameBytes` and
`basic.WithMaxPasswordBytes`, or `apikey.NewStaticWithOptions` with
`apikey.WithMaxKeyIDBytes` and `apikey.WithMaxKeyBytes`, to select smaller limits.
Explicit limits must be positive and cannot exceed the static defaults. The
existing callback API-key authenticator's option behavior is unchanged.

Construction and API-key replacement refuse oversized configured credentials
with `authentication.ErrInvalidConfiguration`, without exposing their values.
Direct authentication refuses oversized fields with `FailureInvalid`; canceled
contexts retain precedence and their original cause. API-key replacement
validates the complete candidate before publication, retaining the old active
set and its immutable limits on failure. A zero-value API-key `Static` uses the
default limits when its first set is installed. Bearer credential-byte admission
is unchanged.

## Principal admission in the prepared root v2 release

`NewPrincipal` retains its signature but now admits at most 8 KiB per retained
string, 256 entries in each audience/tenant-hint/scope list, 64 KiB of retained
string occurrences, and 4096 recursive claim-value occurrences shared across
top-level claims. Existing claim count, depth, and collection limits remain.
Repeated strings, keys, and shared collections are charged for each output
occurrence; interface wrappers add no claim occurrence or depth.

`NewPrincipalWithOptions` and its Principal-local `WithMaxPrincipal…` options
select smaller positive limits, not an override of the ceilings. Admission
failures match `ErrInvalidPrincipal`; invalid options also match
`ErrInvalidConfiguration`. Refusal never truncates identity data or drops claims.
Inventory authoritative static/callback/JWT/OIDC identity producers and their
downstream claim requirements before rollout; do not silently truncate
security-relevant data to fit the new accepted-input contract.

Retained strings have independent backing storage, defined scalar-string types
such as `json.Number` remain intact, and accessors return defensive containers.
`AuthenticatedAt` and its `time.Location` remain unchanged trusted
clock/application metadata outside these budgets. See
[Principal admission and ownership](guides/principal-limits.md) for exact
accounting, caller synchronization, and upstream ownership boundaries.

## From the legacy HTTP and logging adapter paths

Replace imports without changing constructor calls or option ordering:

```text
github.com/faustbrian/go-authentication/v2/authhttp -> github.com/faustbrian/go-authentication/v2/adapters/http
github.com/faustbrian/go-authentication/v2/authlog  -> github.com/faustbrian/go-authentication/v2/adapters/slog
```

The preferred package identifiers are `authenticationhttp` and
`authenticationslog`. The legacy paths remain deprecated, importable facades;
their exported types are aliases of the successors, so assignments, interface
satisfaction, error traversal, and reflection identity remain unchanged.

Both logging paths now represent unfamiliar credential kinds, outcomes, and
nonempty failure kinds as `unknown` instead of logging caller-supplied strings.
Built-in categories and empty failures retain their existing representation.
Adjust log queries that relied on custom category strings; authentication
behavior and the logging record's keys, message, and duration are unchanged.

## From ad hoc middleware

1. Inventory accepted credential locations and disable accidental query or
   cookie support.
2. Move parsing to `authenticationhttp.Extractor`.
3. Move verification to a protocol authenticator.
4. Replace user or session maps in context with `Principal`.
5. Move role and permission checks to authorization after authentication.
6. Map stable failures to the existing client contract without exposing causes.
7. Add optional anonymous policy only to routes that were intentionally public.

## From primitive identities

Replace string user IDs with `PrincipalSpec`. Use subject for stable identity,
method for the authentication mechanism, issuer and audience for trust
context, and authenticated-at for credential age. Copy only bounded claims
needed by downstream policy. Do not place mutable user records in claims.

## From another JWT or OIDC library

Declare exact issuer, audience/client ID, algorithms, clock, skew, key source,
and bounds. Test existing tokens for required `sub`, `iss`, `aud`, `iat`, and
`exp`; reject tokens relying on implicit algorithm selection or missing key IDs.
For OIDC multi-audience tokens, ensure `azp` names the client. Add nonce
validation for interactive flows.

Before rollout, run old and new validation against a sanitized interoperability
corpus, compare only classifications and principals, then canary unavailable
and rejected rates.

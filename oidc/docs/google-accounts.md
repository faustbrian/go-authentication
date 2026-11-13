# Explicit Google Accounts issuer policy

[Documentation index](README.md) · [Generic strict policy](specification-decisions.md)

`NewGoogleAccounts(ctx, Config)` and
`NewGoogleAccountsWithKeySet(Config, KeySet)` select only Google's documented
ID-token issuer compatibility. They do not implement Google OAuth redirects,
token exchange, UserInfo, account linking, signup, sessions or a provider catalog.

## Selected policy and source

| Boundary | Decision |
| --- | --- |
| Startup issuer | Exactly `https://accounts.google.com`; no trimming, URL normalization, port, path, query or alternate spelling |
| Signed token issuer | Exactly `https://accounts.google.com` or `accounts.google.com` |
| Admitted identity | Canonical `Principal.Issuer()` is `https://accounts.google.com`; `Subject()` retains the validated exact subject |
| Discovery | The existing bounded `New` fetches the canonical HTTPS well-known URL and requires exact canonical metadata issuer |
| Keys and HTTP | Existing bounded discovery/JWKS validation, cache/refresh, timeout and caller transport/egress policy remain unchanged |
| Cryptographic input | The original compact token is verified without rewriting its header, payload, issuer or signature |
| Other checks | Existing algorithm, subject, audience/azp, numeric-date, configured nonce, principal admission and supplied token-hash checks are unchanged |
| Unselected constructors | `New` and `NewWithKeySet` retain strict byte-for-byte issuer matching, including rejection of Google's legacy token form |

Authority: Google's [OpenID Connect guide, Validating an ID token](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken),
reviewed on 2026-11-13, explicitly lists these two token issuer values. This is
a named provider compatibility policy, not generic URL equivalence or a change
to OpenID's strict default issuer rule. It does not enable arbitrary issuer
aliases or discovery at a token-supplied location.

Discovery evidence reuses the existing official Google snapshot
`testdata/google-openid-configuration-2026-08-09.json`, pinned in
[`specification/manifest.tsv`](../specification/manifest.tsv) at SHA-256
`f86b185fd428f81d7efaa83ec256693b3abedb57ddfcc6a826f5f396b4827f02`.
It pins the observed canonical discovery and JWKS endpoints; it is not a live
Google result or a currently issued Google ID token.

## Caller usage and ownership

Use the discovery-backed constructor when the application needs the existing
bounded provider discovery and remote key owner:

```go
validator, err := oidc.NewGoogleAccounts(ctx, oidc.Config{
    Issuer: "https://accounts.google.com", ClientID: clientID,
    Algorithms: []string{"RS256"}, Clock: clock.System{},
    NonceValidator: noncePolicy,
})
```

If a trusted signing-key provider is already configured, select
`NewGoogleAccountsWithKeySet` with the same configuration instead. It does no
network IO during construction; its caller owns the key provider and its
resource lifetime. The discovery constructor inherits `New`'s synchronous
bounded acquisition and refresh, with no new goroutine or shutdown owner.
`Config` and the existing constructors/signatures are unchanged.

Then call the existing `ValidateIDToken`, `ValidateBearer` or `Authenticate`.
For each initiating flow, the caller still supplies the correct nonce policy
and applicable `TokenBinding`. Omitted binding input cannot be inferred by this
module. Do not infer recent authentication from `iat` when `auth_time` is absent.
Configuration and nonce/key/clock/transport collaborators have the same bounded,
concurrent-safe ownership obligations as the generic constructors.

Canonicalization happens only after the original token passed the existing
verifier. It gives the two documented token forms one issuer/subject account
namespace. Callers must explicitly bind this constructor selection into their
configuration identity and keep prior in-flight semantics; this package does
not authorize changing an existing account's issuer or replaying a callback.

## Evidence and limitations

`TestGoogleAccountsWithKeySetProjectsCanonicalIdentity` uses real signatures,
both issuer forms, nonce and access/code hashes, and proves the signature owner
receives the unchanged compact token. The discovery-backed public consumer
uses the pinned Google document, a transport boundary double and real JWK
signature validation through the actual bounded discovery/key owner. It does
not replace that owner with a signer or identity stub.

Deterministic cases reject unlisted configuration/issuer forms, wrong signing
keys, audience/azp/nonce/time/hash inputs, canceled/expired callers, legacy
metadata issuer and oversized key responses. Strict default and immutable
concurrent validation remain covered. Bounded issuer fuzzing signs its inputs
and compares selected versus unselected acceptance.

No live Google interoperability, full OAuth relying-party flow, provider
catalog completion or identity/native integration is claimed. Those consumers
must adopt this explicit contract separately. Update the reviewed authority
and corresponding signed-token/discovery cases if Google changes its documented
issuer values; do not widen a generic alias list or normalize arbitrary URLs.

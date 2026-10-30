# Opaque bearer tokens

[Documentation index](../README.md)

Use `bearer.New` with `bearer.ValidatorFunc` or a `bearer.Validator`
implementation. The callback receives a bounded token and must return a
principal whose method is `bearer`.

For small configured token sets, use `bearer.NewStatic`. It compares every
well-formed credential against every active token using keyed fixed-size
digests. Call `Static.Replace` with the complete desired set to atomically add
an overlap token or remove a retired token; failed replacements leave the
previous set active.

Return a classified rejection for an unknown or expired token. Return an
unavailable failure for a context-bounded database or introspection outage.
Never include the token in callback errors. Outbound OAuth token acquisition
and token issuance are outside this project.

See `bearer.ExampleNew`, `bearer.ExampleNewStatic`, and the HTTP quickstart.

## Laravel Sanctum tokens

Services migrated from Laravel use `adapters/laravelsanctum` (AUTH-DEC-014).
`laravelsanctum.NewValidator` parses `id|secret` and pipe-free tokens the way
Sanctum's `findToken` does, rejects malformed tokens before any lookup, and
passes a `Token` to your `Resolver`. Look the token up by `Token.ID` when
present, otherwise by `Token.Digest`, and compare the stored digest with
`Token.Matches` after decoding Sanctum's hex column. The resolver owns expiry,
revocation, owner status and abilities. Wrap the validator with `bearer.New`,
and enable `WithBearerPipe` on the HTTP bearer source. See
`laravelsanctum.ExampleNewValidator`.

Continue with [Exported API map](../api.md).

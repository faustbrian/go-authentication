# API keys

[Documentation index](../README.md)

`apikey.NewStatic` stores fixed-size, per-authenticator keyed ID and secret
digests, compares the complete active set, and returns principals with method
`api_key`.
`apikey.New` adapts a database or secret-service validator.

The HTTP adapter requires separate ID and secret names. Enable exactly one of
`APIKeyHeader` or `APIKeyCookie`; headers are preferred. URL query sources are
not supported because URLs are commonly retained by proxies and analytics. Treat the ID as routing
metadata, not authentication by itself.

A key without an ID sent in one proprietary header uses `APIKeySingleHeader`
(AUTH-DEC-013). The header name matches case-insensitively, more than one
value is ambiguous, and the value must be non-empty visible ASCII without
commas within `WithAPIKeyMaxBytes`. The credential has an empty key ID, so
`apikey.New` and `apikey.NewStatic` refuse it; validate it with your own
`Authenticator` or forward it to the service that owns the key. Add
`WithAPIKeyRejectAuthorization` when a request that also carries any
`Authorization` field must fail as ambiguous. See
`authenticationhttp.ExampleAPIKeySingleHeader`.

For rotation, call `Static.Replace` with a complete new set. Validation builds
the candidate set first and publishes it atomically, so a failed replacement
leaves the previous keys active. See `apikey.ExampleStatic_Replace`.

Continue with [Exported API map](../api.md).

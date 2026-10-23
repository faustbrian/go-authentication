# HTTP authentication

[Documentation index](../README.md)

`authenticationhttp.NewExtractor` evaluates all explicitly configured sources in order
and requires exactly one credential. Duplicate Authorization fields, repeated
query parameters or cookies, partial API keys, and credentials present in more
than one source are rejected.

Header sources are `BasicAuthorization`, `BearerAuthorization`, and
`APIKeyHeader`. Query and cookie sources exist only through explicit bearer or
API-key constructors. The extractor never reads the request body.

Bearer sources enforce RFC 6750 `b64token` syntax by default. Pass
`WithBearerPipe` only when an existing opaque-token contract requires a pipe
delimiter. The option applies consistently to header and cookie bearer
sources.

Root v3 has no query-string credential sources. Query secrets can be copied
into browser history, referrers, reverse-proxy logs, and access logs before
this package receives the request, so send credentials in headers or
explicitly named cookies.

`NewMiddleware` authenticates, stores the principal under a private context
key, and passes the original `http.ResponseWriter`, preserving optional
interfaces. It returns 401 for credential failures and 503 for unavailable or
unclassified failures. A credential failure without a valid failure-specific or
fallback challenge also returns 503 because RFC 9110 forbids a bare 401.
Configure fallback challenges with `WithChallenges`. Challenges are sorted and
quoted safely.

The middleware does not authorize. See `authenticationhttp.ExampleNewMiddleware`.

Continue with [Exported API map](../api.md).

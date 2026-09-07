# JWT and remote JWK validation

Install the optional module:

```sh
go get github.com/faustbrian/go-authentication/jwt
```

`jwt.New` requires one issuer, one audience, an explicit algorithm allow-list,
a clock, and exactly one static `jwk.Set` or `KeyProvider`. Compact tokens must
contain a permitted `alg`, non-empty `kid`, signature, subject, issuer,
audience, issued-at time, and expiration. Duplicate JSON members, unsupported
critical headers, excessive claims or nesting, unknown keys, and algorithm/JWK
metadata mismatches are rejected.

`jwt.NewRemote` owns its JWX cache. Supply a bounded initialization context,
HTTPS JWK URL, bounded refresh intervals and response size as needed, and
always call `Remote.Shutdown` during shutdown. A successful constructor does
not transfer provider lifetime ownership to its initialization context.
`Refresh` is synchronous and preserves the previous cached set on failure.
Plain HTTP requires the explicit development option.

See `jwt.ExampleNew`. Production services should normally use asymmetric keys;
the example uses HMAC only to remain compact and self-contained.

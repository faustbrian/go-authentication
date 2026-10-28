# JWT validation

`jwt` validates signed compact JWTs at the authentication boundary. It owns
JWT/JWS parsing, signature and claim policy, static JWK sets, and a bounded
remote JWKS cache. It does not extract HTTP credentials, discover OIDC
providers, issue tokens, manage sessions, or make authorization decisions.

## Install

```sh
go get github.com/faustbrian/go-authentication/jwt/v2@v2.0.0
```

Version 2 composes with root v3 (`github.com/faustbrian/go-authentication/v3`).
It removed the deprecated `Clock` alias and `Remote.Close`; pass a
`clock.Clock` and call `Remote.Shutdown`. The v1 module remains published for
root v1 but receives no further releases.

Failed remote initialization can take one additional initialization-timeout
interval for cleanup; transports must cooperate with cancellation. The
[changelog](CHANGELOG.md) records the admission and refresh-result repairs.

## Quick start

```go
validator, err := jwt.New(jwt.Config{
	Issuer:     "https://issuer.example.com",
	Audience:   "orders",
	Algorithms: []jwa.SignatureAlgorithm{jwa.RS256()},
	KeySet:     keys,
	Clock:      clock,
})
if err != nil {
	return err
}

principal, err := validator.ValidateBearer(ctx, compactToken)
```

When using remote keys, the caller owns the returned `Remote` and must call
`Shutdown(ctx)` with a bounded context.

The compiling examples in this module contain complete imports and setup.

## Guarantees and limitations

The [complete guide](docs/reference.md) defines ownership, failure semantics,
bounds, concurrency, security, and unsupported behavior. Do not infer
additional guarantees beyond the documented module boundary.

## Documentation

- [Documentation index](docs/README.md)
- [Complete technical guide](docs/reference.md)
- [Specification decision register](docs/specification-decisions.md)
- [Go API reference](https://pkg.go.dev/github.com/faustbrian/go-authentication/jwt)
- [Parent package documentation](../docs/README.md)

## Compatibility and support

This module follows Semantic Versioning. Report vulnerabilities through the
[parent security policy](../SECURITY.md).

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT. See [LICENSE](LICENSE).

# JWT validation

`jwt` validates signed compact JWTs at the authentication boundary. It owns
JWT/JWS parsing, signature and claim policy, static JWK sets, and a bounded
remote JWKS cache. It does not extract HTTP credentials, discover OIDC
providers, issue tokens, manage sessions, or make authorization decisions.

## Install

```sh
go get github.com/faustbrian/go-authentication/jwt@v1
```

The `v1.1.4` patch candidate keeps the existing JWT import path and published
root-v1 principal types. Once published, update this independent nested module
with `go get github.com/faustbrian/go-authentication/jwt@v1.1.4`; adopting this
patch does not require a root-v2 or OIDC upgrade. Preparation is not publication.

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
`Shutdown(ctx)` with a bounded context. Deprecated `Close(ctx)` delegates to
the same complete cleanup operation.

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

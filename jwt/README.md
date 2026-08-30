# JWT validation

`jwt` validates signed compact JWTs at the authentication boundary. It owns
JWT/JWS parsing, signature and claim policy, static JWK sets, and a bounded
remote JWKS cache. It does not extract HTTP credentials, discover OIDC
providers, issue tokens, manage sessions, or make authorization decisions.

## Install

```sh
go get github.com/faustbrian/go-authentication/jwt@v1
```

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

## License

MIT. See [LICENSE](LICENSE).

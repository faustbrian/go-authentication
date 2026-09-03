# OIDC ID-token validation

`oidc` discovers an OpenID Provider and validates signed OpenID Connect ID
tokens. It owns the authentication trust boundary only: applications retain
OAuth authorization flows, redirects, sessions, cookies, middleware, nonce
storage, and authorization policy.

The module implements the OpenID Connect Core 1.0 ID-token validation rules and
OpenID Connect Discovery 1.0 provider metadata rules. It supports the
authorization-code, implicit, and hybrid ID-token profiles with asymmetric
`RS*`, `PS*`, `ES*`, and `EdDSA` signatures. The provider MUST advertise every
configured algorithm and MUST advertise `RS256`, as required by Discovery.
Symmetric client-secret signatures, encrypted ID tokens, distributed claims,
OAuth flow execution, UserInfo, logout, dynamic registration, and access-token
validation are deliberately excluded.

## Install

```sh
go get github.com/faustbrian/go-authentication/oidc@v1
```

## Quick start

```go
validator, err := oidc.New(ctx, oidc.Config{
	Issuer:     "https://accounts.example.com/tenant",
	ClientID:   "web-client",
	Algorithms: []string{"RS256"},
	Clock:      clock.System{},
	NonceValidator: oidc.NonceValidatorFunc(
		func(ctx context.Context, nonce string) error {
			return nonceStore.Consume(ctx, nonce)
		},
	),
})
if err != nil {
	return err
}

principal, err := validator.ValidateIDToken(ctx, rawIDToken, oidc.TokenBinding{
	AccessToken:       accessToken,
	AuthorizationCode: authorizationCode,
})
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
- [Go API reference](https://pkg.go.dev/github.com/faustbrian/go-authentication/oidc)
- [Parent package documentation](../docs/README.md)

## Compatibility and support

This module follows Semantic Versioning. Report vulnerabilities through the
[parent security policy](../SECURITY.md).

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.3.0/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.3.0/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT. See [LICENSE](LICENSE).

# authentication

[![CI](https://github.com/faustbrian/go-authentication/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/faustbrian/go-authentication/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-required-blue)](https://github.com/faustbrian/go-authentication/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Mutation](https://img.shields.io/badge/mutation-100%25_required-blue)](CONTRIBUTING.md#verification)
[![Documentation](https://img.shields.io/badge/docs-checked_in_CI-blue)](docs/)
[![Go Reference](https://pkg.go.dev/badge/github.com/faustbrian/go-authentication.svg)](https://pkg.go.dev/github.com/faustbrian/go-authentication)
[![Release](https://img.shields.io/github/v/release/faustbrian/go-authentication?sort=semver)](https://github.com/faustbrian/go-authentication/releases)
[![Go](https://img.shields.io/badge/go-1.26.6-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`authentication` is a production-oriented authentication library for Go
services. It turns Basic credentials, opaque bearer tokens, API keys, JWTs, or
OIDC ID tokens into an immutable principal. It does not decide whether that
principal may perform an action.

The root, Basic, bearer, API-key, HTTP, logging, and test packages use only the
Go standard library plus the narrow `clock` capability contracts. JWT,
OIDC, and OpenTelemetry live in separate modules so their larger dependency
graphs are opt-in.

## Requirements

- Go 1.26 or newer.
- `clock` v1 for deterministic time seams.
- `jwt`: lestrrat-go/jwx v3.
- `oidc`: coreos/go-oidc v3 and go-jose v4.
- `authotel`: OpenTelemetry API v1.44.

## Install

```sh
go get github.com/faustbrian/go-authentication
```

Add an optional module only when needed:

```sh
go get github.com/faustbrian/go-authentication/jwt
go get github.com/faustbrian/go-authentication/oidc
go get github.com/faustbrian/go-authentication/authotel
```

## Five-minute quickstart

```go
extractor, err := authhttp.NewExtractor(authhttp.BearerAuthorization())
if err != nil {
	return err
}

authenticator, err := bearer.New(bearer.ValidatorFunc(
	func(ctx context.Context, token string) (authentication.Principal, error) {
		if token != configuredToken {
			return authentication.Principal{},
				authentication.NewFailure(authentication.FailureRejected)
		}
		return authentication.NewPrincipal(authentication.PrincipalSpec{
			Subject: "orders-worker",
			Method:  "bearer",
		})
	},
))
if err != nil {
	return err
}

middleware, err := authhttp.NewMiddleware(extractor, authenticator)
if err != nil {
	return err
}

handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	principal, ok := authentication.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "authentication invariant failed", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, principal.Subject())
}))
```

The middleware is fail-closed. It authenticates and stores the principal, but
it deliberately performs no role, permission, ownership, or policy checks.

## Packages

| Package | Purpose |
| --- | --- |
| root | Immutable principals, typed credentials, failures, composition, instrumentation |
| `basic` | Constant-work static Basic authentication |
| `bearer` | Callback and interface adapters for opaque tokens |
| `apikey` | Callback and atomically rotatable static API keys |
| `authhttp` | Strict extraction, challenges, and authentication-only middleware |
| `authlog` | Secret-safe standard `log/slog` instrumentation |
| `authtest` | Deterministic principals, clocks, authenticators, HTTP fixtures, assertions |
| `jwt` | Optional strict JWT/JWK validation and owned remote cache |
| `oidc` | Optional OIDC discovery and ID-token validation without background refresh |
| `authotel` | Optional OpenTelemetry traces and bounded metrics |

## Security defaults

- Credential values always format as redacted.
- Static secrets are compared through per-authenticator keyed HMAC-SHA-256
  digests with constant-time comparison.
- Multiple credential sources are rejected as ambiguous.
- A `401 Unauthorized` response is emitted only with at least one valid
  `WWW-Authenticate` challenge; missing challenge metadata fails as unavailable.
- Query and cookie credentials are disabled unless explicitly configured.
- Query credential constructors are deprecated for new designs because URLs
  can be retained before the extractor sees them.
- Claims, tokens, keys, HTTP bodies, and cache work have explicit bounds.
- JWT algorithms, issuer, audience, key ID, key metadata, and time claims are
  validated explicitly.
- OIDC uses upstream protocol verification with bounded synchronous JWK
  refresh and stale known-key availability during issuer outages.
- Instrumentation receives only credential kind, outcome, failure kind, and
  duration; it never receives credential or principal contents.

## Documentation

Start with the [quickstart](docs/quickstart.md). Protocol-specific guides are
under [docs/guides](docs/guides), including HTTP, JSON-RPC, service accounts,
credential rotation, and anonymous routes. Operational and compatibility
material is in [docs/operations.md](docs/operations.md),
[docs/troubleshooting.md](docs/troubleshooting.md), and
[docs/compatibility.md](docs/compatibility.md). Observable protocol choices are
recorded in the
[specification decision register](docs/specification-decisions.md).

For a security review or rollout, use the [adoption checklist](docs/adoption.md),
[threat model](docs/security/threat-model.md),
[findings](docs/security/findings.md), and
[test matrices](docs/security/test-matrices.md).

The authentication-versus-authorization boundary is documented in
[docs/authentication-vs-authorization.md](docs/authentication-vs-authorization.md).
Security reports follow [SECURITY.md](SECURITY.md), and contributions follow
[CONTRIBUTING.md](CONTRIBUTING.md).

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.3.0/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.3.0/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT. See [LICENSE](LICENSE).

# authotel

`authotel` is the deprecated compatibility path for the preferred
[`adapters/otel`](https://pkg.go.dev/github.com/faustbrian/go-authentication/adapters/otel)
OpenTelemetry adapter for
[`authentication`](https://pkg.go.dev/github.com/faustbrian/go-authentication).
It turns completed authentication attempts into bounded traces and metrics. It
does not authenticate credentials, make authorization decisions, configure an
SDK, or own exporters.

This module retains its original instrumentation scope and behavior. The new
module is intentionally separate so applications remaining on this path do not
receive a silent telemetry-scope rename.

It is a stable v1 compatibility module with deprecated lifecycle status. It
supports Go 1.27.0 or newer on portable Go platforms and requires explicit
caller-owned OpenTelemetry tracer and meter providers.

## Install

New code should install the successor:

```sh
go get github.com/faustbrian/go-authentication/adapters/otel@v1
```

The released path remains supported for the longer of 180 days and two
published stable minor releases after the successor is publicly consumable,
and removal requires an authorized next-major release:

```sh
go get github.com/faustbrian/go-authentication/authotel@v1
```

## Quick start

```go
instrumenter, err := authotel.New(authotel.Config{
	TracerProvider: tracerProvider,
	MeterProvider:  meterProvider,
})
if err != nil {
	return err
}

authenticator, err := authentication.NewInstrumentedWithBegin(
	baseAuthenticator,
	instrumenter,
	clock,
)
```

The [compiling example](example_test.go) contains complete imports and setup.

## Package map and selection

The module contains one package, whose default import identifier is `authotel`.
Use it only to preserve the released import path and telemetry scope while
migrating. New integrations should use `adapters/otel`. Neither path configures
an SDK, authenticates credentials, authorizes principals, or owns providers.

## Guarantees and limitations

The [complete guide](docs/reference.md) defines ownership, failure semantics,
bounds, concurrency, security, and unsupported behavior. Do not infer
additional guarantees beyond the documented module boundary.

## Documentation

- [Documentation index](docs/README.md)
- [Complete technical guide](docs/reference.md)
- [Go API reference](https://pkg.go.dev/github.com/faustbrian/go-authentication/authotel)
- [FAQ and troubleshooting](docs/reference.md#faq-and-troubleshooting)
- [Testing helpers](https://pkg.go.dev/github.com/faustbrian/go-authentication/authtest)
- [Parent package documentation](../docs/README.md)

## Compatibility and support

This module follows Semantic Versioning. Report vulnerabilities through the
[parent security policy](../SECURITY.md).

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT. See [LICENSE](LICENSE).

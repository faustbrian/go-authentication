# authentication OpenTelemetry adapter

`adapters/otel` is the preferred optional OpenTelemetry adapter for
[`authentication`](https://pkg.go.dev/github.com/faustbrian/go-authentication).
It turns completed authentication attempts into bounded traces and metrics. It
does not authenticate credentials, make authorization decisions, configure an
SDK, or own exporters.

## Requirements

- Go 1.26.6 or newer.
- Portable Go; no operating-system service is required.
- Explicit caller-owned OpenTelemetry tracer and meter providers.

The module is a stable, independently releasable adapter. It is safe for
concurrent use and owns no goroutine, exporter, provider, or shutdown work.

## Install

```sh
go get github.com/faustbrian/go-authentication/adapters/otel@v1
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
Use it when bounded authentication outcomes must become OpenTelemetry signals.
Do not use it to configure an SDK, authenticate credentials, authorize a
principal, or attach identity and credential contents to telemetry.

Applications that do not need OpenTelemetry should not construct this adapter.
No global or no-op provider is selected implicitly.

## Guarantees and limitations

The [complete guide](docs/reference.md) defines ownership, failure semantics,
bounds, concurrency, security, and unsupported behavior. Do not infer
additional guarantees beyond the documented module boundary.

## Documentation

- [Documentation index](docs/README.md)
- [Complete technical guide](docs/reference.md)
- [Go API reference](https://pkg.go.dev/github.com/faustbrian/go-authentication/adapters/otel)
- [FAQ and troubleshooting](docs/reference.md#faq-and-troubleshooting)
- [Testing helpers](https://pkg.go.dev/github.com/faustbrian/go-authentication/authtest)
- [Parent package documentation](../../docs/README.md)

## Compatibility and support

This module follows Semantic Versioning. Report vulnerabilities through the
[parent security policy](../../SECURITY.md).

The released `github.com/faustbrian/go-authentication/authotel` module remains
supported for the longer of 180 days and two published stable minor releases
after this successor is publicly consumable, and retains its original telemetry
scope. Removal additionally requires an authorized next-major release.
Migrating to this module preserves signal names, units, attributes, provider
ownership, and completion behavior, while the instrumentation scope changes to
this module's target-oriented import path. See the
[changelog](CHANGELOG.md), [support policy](../../SUPPORT.md), and
[migration guidance](docs/reference.md#migration-and-compatibility).

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT. See [LICENSE](LICENSE).

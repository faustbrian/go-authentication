# authotel

`authotel` is the optional OpenTelemetry adapter for
[`authentication`](https://pkg.go.dev/github.com/faustbrian/go-authentication).
It turns completed authentication attempts into bounded traces and metrics. It
does not authenticate credentials, make authorization decisions, configure an
SDK, or own exporters.

## Install

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

authenticator, err := authentication.NewInstrumented(
	baseAuthenticator,
	instrumenter,
	clock,
)
```

The compiling examples in this module contain complete imports and setup.

## Guarantees and limitations

The [complete guide](docs/reference.md) defines ownership, failure semantics,
bounds, concurrency, security, and unsupported behavior. Do not infer
additional guarantees beyond the documented module boundary.

## Documentation

- [Documentation index](docs/README.md)
- [Complete technical guide](docs/reference.md)
- [Go API reference](https://pkg.go.dev/github.com/faustbrian/go-authentication/authotel)
- [Parent package documentation](../docs/README.md)

## Compatibility and support

This module follows Semantic Versioning. Report vulnerabilities through the
[parent security policy](../SECURITY.md).

For ecosystem-wide package selection, construction, ownership, and lifecycle
guidance, see the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/README.md)
and its [Service edge family](https://github.com/faustbrian/go-library-tools/blob/v1.4.0/docs/ecosystem/design-language.md#package-families-and-selection).

## License

MIT. See [LICENSE](LICENSE).

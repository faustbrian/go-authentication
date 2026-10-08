# Changelog

All notable changes to this module are documented here.

## [Unreleased]

### Changed

- Adopt OpenTelemetry 1.47.0, go-authentication v1.2.1 and x/sys v0.48.0
  while preserving bounded telemetry signals and caller-owned providers.

## [1.0.2] - 2026-10-03

### Changed

- Refresh the indirect go-clock dependency while preserving telemetry signal
  names, instrumentation scope, and caller-owned provider lifecycle.

## 1.0.0 - 2026-09-08

### Added

- Introduce the target-oriented OpenTelemetry adapter successor with bounded
  traces and metrics, caller-owned providers, and the preferred `Begin`
  observation operation.
- Publish benchmark environment, corpus, median latency, throughput, and
  allocations for every measured path, with actual and limit values when a
  performance budget fails.

### Migration

- Migrate imports from `github.com/faustbrian/go-authentication/authotel` to
  `github.com/faustbrian/go-authentication/adapters/otel`; construction,
  signal names, units, attributes, and completion behavior remain unchanged.
  The instrumentation scope becomes the successor module path, and deprecated
  `Start` remains available throughout the compatibility interval.

[Unreleased]: https://github.com/faustbrian/go-authentication/compare/adapters/otel/v1.0.2...HEAD
[1.0.2]: https://github.com/faustbrian/go-authentication/compare/adapters/otel/v1.0.1...adapters/otel/v1.0.2

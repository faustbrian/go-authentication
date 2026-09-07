# Changelog

All notable changes to this module are documented here.

## Unreleased

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

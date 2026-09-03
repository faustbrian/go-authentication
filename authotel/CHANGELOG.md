# Changelog

All notable changes to this module are documented here.

## Unreleased

### Changed

- Publish schema-v2 cohesion metadata for the OpenTelemetry adapter and link
  its consumer entry point to the immutable Golib ecosystem index.
- Reconcile `go-authentication` and `go-clock` v1.0.0 with their public SumDB
  identities and adopt the shared v1.4.0 W14 validation contract.

### Documentation

- Link ecosystem and Service edge family guidance to the immutable v1.4.0
  documentation release.
- Move detailed module guidance behind a concise README and documentation index.
- Use human-oriented section names and package-owned documentation links.

## 1.0.0 - 2026-08-25

### Documentation

- Link the package README to package-owned documentation.

### Distribution

- Include the canonical MIT licence in the independently published module.

### Compatibility

- Added a pinned module export baseline so incompatible public API changes
  fail the canonical repository gate.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-authentication/authotel` identity while preserving its documented API and behavior.
- Refresh local `v0.0.0` owned-module checksums after dependency manifests and
  release notes were normalized; runtime behavior and public APIs are
  unchanged.
- Normalize credential, outcome, and failure dimensions to the documented
  closed value sets; clamp negative durations; complete each attempt exactly
  once under duplicate or concurrent callbacks without making duplicates wait
  for provider work; and isolate provider and observer panics without
  disclosing panic values.
- Define adapter telemetry convention version `1.0.0` without mislabeling it as
  an OpenTelemetry instrumentation-module version or schema URL, and document
  signal stability, bounded-provider prerequisites, provider ownership,
  privacy, cancellation, concurrency, lifecycle, compatibility, and migration
  policy.
- Preserve the caller context when a hostile tracer returns nil and release
  captured request context and span references after the winning completion so
  retained callbacks cannot retain request state.
- Expand hardening proof across complete captured-telemetry redaction,
  high-concurrency cardinality, bounded batch-exporter backpressure, hostile
  provider fuzzing, SDK errors and shutdown, and enabled, sampled-out, no-op,
  and direct-instrumentation allocation benchmarks with enforced relative
  latency and allocation budgets.
- Make the unavoidable bounded synchronous-provider prerequisite explicit:
  indefinitely blocking implementations are outside the supported contract
  because containing them would require unbounded abandoned goroutines.
- Require owned sibling modules at local `v0.0.0`; clean external consumers
  pin each module to an exact main pseudo-version.

- Refresh owned-module checksums against the final consolidated archives.
- Normalized standalone module metadata against the canonical owned dependency
  graph, including complete checksums for clean consumer resolution.
- Refreshed the canonical authentication checksum after its test archive
  changed, preserving isolated module verification.
- Refreshed the canonical authentication checksum after its API compatibility
  baseline was normalized to the module boundary.

### Added

- Add an allocation-aware benchmark for the complete authentication
  instrumentation start-and-finish path.
- Add bounded fuzz coverage for arbitrary credential, outcome, failure, and
  duration values across the complete instrumentation lifecycle.

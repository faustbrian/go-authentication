# Deprecation Policy

Deprecations MUST identify the replacement, reason, migration steps, and
earliest removal version. Public Go identifiers use a valid `Deprecated:` doc
paragraph and corresponding changelog entry.

At `v1` and later, a supported replacement SHOULD exist for at least one minor
release before removal. Security or correctness defects MAY require faster
removal when continued support would be unsafe; the release notes must explain
the exception.

Silent behavior changes, undocumented aliases, and indefinite deprecated code
are prohibited. Deprecations are checked during compatibility and release
review.

The root-module `authhttp` and `authlog` paths are deprecated in favor of
`adapters/http` and `adapters/slog`. They remain supported for the longer of
180 days after successor publication and two later stable root minor releases.
Removal also requires owned-consumer migration, external-consumer evidence,
and an authorized major release; the earliest possible removal is v2.0.0.

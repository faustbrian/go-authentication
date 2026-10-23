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

Root v3 removed the deprecated `authhttp` and `authlog` paths, the
Start-named `Instrumenter`, `NewInstrumented` and `Clock` contracts, the
query-string `BearerQuery` and `APIKeyQuery` sources, and stopped maintaining
the `authotel` module, before the announced support window ended. Published
earlier releases keep them; no further releases of superseded majors are
planned.

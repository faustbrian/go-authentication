# Specification provenance

`manifest.tsv` pins the exact RFC 7515 Appendix A.2 compact RS256 JWS and the
RFC 7520 Figure 5 HMAC JWK used by `interoperability_test.go`. The digests and
byte counts apply to the whitespace-free strings embedded in those tests.

The conformance target also runs the supported algorithm/key matrix,
bidirectional golang-jwt interoperability across every shared HMAC, RSA, PSS,
and ECDSA algorithm, deliberately stricter differential cases, adversarial
serialization and claim cases, and remote fault injection.

The canonical
[`docs/specification-decisions.md`](../docs/specification-decisions.md)
register links every observable interpretation and defensive policy to that
executable evidence. This provenance directory pins source material; the
register owns rationale, consequences, and reconsideration conditions.

When an RFC erratum or replacement algorithm specification changes a vector,
retain the previous evidence, add a new versioned row, update the test from the
official source, and recompute the whitespace-free digest and byte count with
`shasum -a 256` and `wc -c`.

The embedded excerpts are manual transcriptions governed by the IETF Trust's
Legal Provisions Relating to IETF Documents. They are retained only as the
minimum interoperability vectors needed by the tests. To update one, copy the
exact compact value or JWK from the linked RFC, remove formatting whitespace,
run `shasum -a 256` and `wc -c` over that exact byte sequence, update its
manifest row, and rerun `make conformance`.


## Decision conformance matrix

| Decision | Authoritative sources | Executable evidence |
| --- | --- | --- |
| [JWT-DEC-001](../docs/specification-decisions.md) | rfc7519-source, rfc7515-source | TestValidatorRejectsNonCanonicalBase64TruncationAndNestedPayloads, TestInspectCompactJWTRejectsEachBoundary, TestRFC7515AppendixA2RS256CompactJWS |
| [JWT-DEC-002](../docs/specification-decisions.md) | rfc8259-source, rfc8725-source | TestValidatorRejectsDuplicateAndOversizedClaims, TestInspectJSONObjectRejectsNonInteroperableUnicodeAndHugeNumbers, TestJSONUnicodeEscapeValidationAcceptsPairsAndRejectsMalformedPairs, TestValidatorRejectsMalformedNumericDates |
| [JWT-DEC-003](../docs/specification-decisions.md) | rfc9864-source, rfc8725-source, rfc7518-source, iana-jose-source | TestSupportedAlgorithmAndKeyMatrix, TestGolangJWTAlgorithmInteroperability, TestValidatorRejectsAlgorithmKeyAndHeaderAttacks |
| [JWT-DEC-004](../docs/specification-decisions.md) | rfc7518-source, rfc7517-source, rfc8725-source | TestValidatorRejectsCryptographicallyUnsafeKeys, TestValidateKeyMaterialRejectsEveryInvalidRepresentation, TestRemoteJWKValidationRejectsEveryKeyPolicyViolation, TestRFC7520HMACJWKInteroperability |
| [JWT-DEC-005](../docs/specification-decisions.md) | rfc7515-source, rfc8725-source | TestValidatorRejectsAlgorithmKeyAndHeaderAttacks, TestInspectCompactJWTRejectsEachBoundary |
| [JWT-DEC-006](../docs/specification-decisions.md) | rfc7519-source, rfc8725-source | TestValidatorRejectsInvalidJWTTrustDecisions, TestValidatorEnforcesSubjectAndRequiredClaimPolicy, TestConfigurationReservesCapacityForMandatoryAndRequiredClaims, TestValidatorRejectsInvalidPrincipalClaims |
| [JWT-DEC-007](../docs/specification-decisions.md) | rfc7519-source | TestValidatorHonorsExactNumericDateBoundaries, TestNumericDateValidationChecksEveryPresentClaimAndDigitBoundary, TestValidatorRejectsMalformedNumericDates, TestValidatorHonorsCancellationAndConfigurationBounds |
| [JWT-DEC-008](../docs/specification-decisions.md) | rfc7517-source, rfc8725-source | TestConfigurationAndKeySetValidationBoundaries, TestValidateBearerAndProviderFailureBoundaries, TestRemoteDoesNotTransferCachedKeyOwnership |
| [JWT-DEC-009](../docs/specification-decisions.md) | rfc9110-source, rfc8725-source, rfc7517-source | TestRemoteRejectsRedirects, TestRemoteRejectsHostileJWKResponsesAtInitialization, TestRemoteConfigurationRejectsEachUnsafeBoundary, TestJWKResponseTransportRejectsBrokenAndOversizedResponses |
| [JWT-DEC-010](../docs/specification-decisions.md) | rfc9111-source | TestRemoteJWKRotationAndIssuerOutage, TestRemoteRefreshTimingHonorsBoundsAndCacheHeaders, TestRemoteRefreshAndAuthenticationAreRaceSafe, TestRemoteRefreshSchedulingHasFleetJitter |
| [JWT-DEC-011](../docs/specification-decisions.md) | rfc9110-source | TestRemoteRefreshWaitersShareResultAndHonorCancellation, TestRemoteSerializesAutomaticAndExplicitRefreshWork, TestRemoteLifetimeIsOwnedByClose, TestRemoteCloseReportsCanceledJoin, TestRemoteCloseDeadlineIsNotBlockedByRefreshLock |
| [JWT-DEC-012](../docs/specification-decisions.md) | rfc8725-source, rfc7519-source | TestProviderFailureIsUnavailableAndSecretSafe, TestRemoteFailureRedactsEndpointQueryAndTransportError, TestValidatorPreservesSafeStandardsErrorCategories, TestRejectedJWTFailureWithoutStandardsCategory |
| [JWT-DEC-013](../docs/specification-decisions.md) | rfc8725-source | TestValidatorRejectsInvalidJWTTrustDecisions, TestValidatorEnforcesSubjectAndRequiredClaimPolicy, TestValidatorRejectsAlgorithmKeyAndHeaderAttacks |
| [JWT-DEC-014](../docs/specification-decisions.md) | rfc8725-source | TestSupportedAlgorithmAndKeyMatrix, TestGolangJWTAlgorithmInteroperability, TestValidatorRejectsAlgorithmKeyAndHeaderAttacks |
| [JWT-DEC-015](../docs/specification-decisions.md) | rfc7515-source | TestValidatorRejectsAlgorithmKeyAndHeaderAttacks, TestInspectCompactJWTRejectsEachBoundary, TestDifferentialValidationKeepsExplicitlyStricterPolicy |

# Specification provenance

`manifest.tsv` pins the exact RFC 7617 and RFC 6750 interoperability vectors
executed by `authhttp/interoperability_test.go`. Digests and byte counts apply
to the encoded credential or token string exactly as embedded in the test.

The canonical
[`docs/specification-decisions.md`](../docs/specification-decisions.md)
register maps normative and package-owned behavior to focused tests,
hostile-input fuzzing, and security matrices. The manifest does not claim that
three positive vectors replace the complete RFC requirements.

When an RFC erratum or replacement changes a vector, retain the previous
evidence, add a versioned row, copy the exact value from the authoritative
source, and recompute its digest and byte count with `shasum -a 256` and
`wc -c`. Update the decision register and executable evidence in the same
change.

The embedded excerpts are retained only as the minimum interoperability values
needed by the tests and are governed by the IETF Trust's Legal Provisions
Relating to IETF Documents.


## Decision conformance matrix

| Decision | Authoritative sources | Executable evidence |
| --- | --- | --- |
| [AUTH-DEC-001](../docs/specification-decisions.md) | rfc9110-source | TestBasicAuthorizationExtractionIsStrict, TestBearerAuthorizationExtractionEnforcesGrammarAndBounds |
| [AUTH-DEC-002](../docs/specification-decisions.md) | rfc7617-source | TestRFC7617BasicCredentialVectors, TestBasicAuthorizationExtractionIsStrict, TestBasicAuthorizationPreservesOctetsAndPasswordColons |
| [AUTH-DEC-003](../docs/specification-decisions.md) | rfc6750-source | TestRFC6750BearerHeaderVector, TestBearerAuthorizationExtractionEnforcesGrammarAndBounds, TestBearerAuthorizationPipeRequiresExplicitOptIn, TestPrivateTokenAndNameBoundaries |
| [AUTH-DEC-004](../docs/specification-decisions.md) | rfc6750-source | TestBearerQueryAndCookieAreExplicitSources, TestNamedBearerSourcesRejectAbsentDuplicateAndHostileValues, TestMiddlewareAuthenticatesWithoutReadingBodyOrWrappingWriter |
| [AUTH-DEC-005](../docs/specification-decisions.md) | rfc9110-source | TestAPIKeySourcesMustBeExplicitAndRejectDuplicates, TestAPIKeySourcesRejectMalformedQueriesAndBoundedValues, TestStaticAuthenticatesKeyByDeterministicID, TestStaticRotationAtomicallyReplacesActiveKeys, TestStaticRejectsDuplicateKeyConfiguration |
| [AUTH-DEC-006](../docs/specification-decisions.md) | rfc9110-source, rfc6750-source | TestBasicAuthorizationExtractionIsStrict, TestAPIKeySourcesMustBeExplicitAndRejectDuplicates, TestExtractorSeparatesOriginAndProxyCredentials |
| [AUTH-DEC-007](../docs/specification-decisions.md) | rfc9110-source | TestFormatChallengeSortsAndEscapesParameters, TestMiddlewareFailsClosedWithChallengesAndRedaction, TestMiddlewareUsesChallengeFromFailure, TestMiddlewareTreatsMissingOrInvalidFailureChallengesAsUnavailable |
| [AUTH-DEC-008](../docs/specification-decisions.md) | rfc6750-source, rfc9110-source | TestMiddlewareFailsClosedWithChallengesAndRedaction, TestOptionalMiddlewareAllowsOnlyAbsentCredentials, TestMiddlewareRejectsInvalidConfigurationAndResult, TestMiddlewarePropagatesRequestCancellation, TestMiddlewareTreatsMissingOrInvalidFailureChallengesAsUnavailable |
| [AUTH-DEC-009](../docs/specification-decisions.md) | rfc9110-source, rfc6750-source | TestCompositeFallsThroughOnlyRejectedAuthenticators, TestCompositeStopsOnNonRejectedFailure, TestCompositeCombinesRejectedChallenges, TestCompositeRejectsInvalidConfigurationAndResults |
| [AUTH-DEC-010](../docs/specification-decisions.md) | rfc7617-source, rfc6750-source | TestStaticAuthenticatesConfiguredBasicCredential, TestStaticRejectsUnsafeConfiguration, TestStaticAcceptsExactEntryLimitAndKeepsEarlierMatch, TestStaticRotatesBoundedBearerKeysAtomically, TestStaticBearerRotationIsRaceSafe, TestStaticBearerFailedReplacementKeepsPreviousSet, TestStaticAuthenticatesKeyByDeterministicID, TestStaticRotationAtomicallyReplacesActiveKeys, TestStaticRotationIsRaceSafe, TestStaticRejectsDuplicateKeyConfiguration |
| [AUTH-DEC-011](../docs/specification-decisions.md) | rfc6750-source | TestBearerSourcesRejectMultipleTransmissionMethods |
| [AUTH-DEC-012](../docs/specification-decisions.md) | rfc9110-source | TestMiddlewareFailsClosedWithChallengesAndRedaction, TestMiddlewareUsesChallengeFromFailure, TestMiddlewareTreatsMissingOrInvalidFailureChallengesAsUnavailable |

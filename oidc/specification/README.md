# Specification provenance

`manifest.tsv` pins the OpenID Connect Core 1.0 Section 2 ID-token claims
vector used by the conformance test. The local JSON fixture preserves the
claims from the final specification incorporating errata set 2; its digest and
byte count detect accidental drift.

The conformance target runs the package's complete specification-derived
discovery, metadata, JOSE, ID-token, audience, nonce, time, error, and option
matrices in addition to that pinned example. The OpenID Foundation conformance
suite was reviewed at revision `6b8b809dd07df6ca8b4481a9e921bf48b9ffbffe`
on 2026-08-09. Its OpenID Connect RP profiles require a complete HTTP relying
party to perform authorization redirects, callbacks, token exchange, and
optional UserInfo processing. Those profiles are not directly runnable or
certifiable against this discovery/JWKS/ID-token-validation package alone; a
wrapper RP result would be composite evidence, not package-only conformance.

The canonical
[`docs/specification-decisions.md`](../docs/specification-decisions.md)
register links every observable interpretation and defensive policy to that
evidence. This directory pins source provenance; the register owns rationale,
consequences, and reconsideration conditions.

Provider interoperability tests use minimal standards-compliant metadata
shapes representative of Google, Keycloak, and Dex. They are compatibility
profiles, not copied provider snapshots or claims of certification against a
live provider version.

The interoperability gate also starts Keycloak 26.3.2 from the immutable OCI
image digest pinned in `scripts/test-oidc-keycloak-interoperability.sh`, imports
the checksummed realm fixture, obtains an ephemeral provider-issued ID token,
and validates it against that instance's real discovery document and JWKS. The
token is deleted with the task-owned temporary directory and is not an
interoperability fixture.

The dated Google metadata fixture was fetched from Google's public discovery
endpoint on 2026-08-09. It is immutable interoperability evidence for that
observed provider document, not a claim about Google's current or certified
state after that date.

## Fixture maintenance

- `oidc-core-section-2.json` is a minimal manual transcription of the claims in
  OpenID Connect Core 1.0 Section 2 and is governed by the OpenID Foundation's
  specification copyright and IPR policy. Update it only when the pinned final
  specification changes, then validate it with `jq -e .` and refresh the digest
  and byte count in `manifest.tsv` with `shasum -a 256` and `wc -c`.
- `google-openid-configuration-2026-08-09.json` contains factual metadata
  published by the provider; no source-code license is asserted. Re-fetch a
  newly dated snapshot with `curl --fail --silent --show-error --output FILE
  https://accounts.google.com/.well-known/openid-configuration`, retain the old
  dated snapshot, then validate and record its digest and byte count as above.
- `keycloak-26.3.2-realm.json` is repository-authored test configuration under
  this repository's license. Update it by editing the JSON for the newly pinned
  Keycloak image, run `jq -e .`, refresh its manifest digest and byte count, and
  run `scripts/test-oidc-keycloak-interoperability.sh` to prove the imported
  realm still issues a token accepted through real discovery and JWKS.


## Decision conformance matrix

| Decision | Authoritative sources | Executable evidence |
| --- | --- | --- |
| [OIDC-DEC-001](../docs/specification-decisions.md) | oidc-discovery-source, oidc-core-source | TestNewPreservesDiscoveryDeadlineAndRejectsIssuerMismatch, TestValidatorRequiresExactIssuerDespiteUpstreamCompatibilityAliases, TestConfigurationRejectsEachInvalidBoundary |
| [OIDC-DEC-002](../docs/specification-decisions.md) | oidc-discovery-source, rfc8259-source | TestProviderMetadataValidationMatrix, TestNewRejectsDuplicateDiscoveryMembersBeforeFetchingKeys, TestNewRejectsNullOptionalProviderMetadata, TestNewRejectsSigningAlgorithmsNotAdvertisedByProvider |
| [OIDC-DEC-003](../docs/specification-decisions.md) | oidc-discovery-source, rfc9110-source | TestGoogleProviderMetadataSnapshot, TestRemoteURLValidationRejectsEachUnsafeComponent, TestHTTPHardeningAndBoundedReaders, TestDiscoveryAndJWKRequestsAreBoundedAndCancelable |
| [OIDC-DEC-004](../docs/specification-decisions.md) | rfc7518-source, oidc-core-source, oidc-discovery-source, rfc7517-source | TestJOSEKeyAlgorithmFamilies, TestRemoteFetchIgnoresUnrelatedEncryptionKeys, TestRemoteFetchRejectsAmbiguousJWKMetadata, TestVerifyWithKeysRejectsMissingKeyIDForAmbiguousSet, TestKeycloakProviderIssuedIDToken |
| [OIDC-DEC-005](../docs/specification-decisions.md) | rfc7515-source, oidc-core-source, rfc8259-source | TestValidatorRejectsMalformedBoundedAndDuplicateTokens, TestInspectCompactTokenRejectsEachBoundary, TestValidatorRejectsClaimsThatCannotBeDecodedLosslessly, TestValidatorPreservesPrivateNumbersAndRejectsInvalidUnicode |
| [OIDC-DEC-006](../docs/specification-decisions.md) | oidc-core-source | TestValidatorEnforcesOIDCClaimsAndAuthorizedParty, TestValidatorRejectsUntrustedAdditionalAudiences, TestValidatorRejectsNonASCIIOrOversizedSubject, TestOpenIDConnectCoreIDTokenClaimVector |
| [OIDC-DEC-007](../docs/specification-decisions.md) | rfc7519-source, oidc-core-source | TestNumericDateBoundariesAndFraction, TestValidatorAppliesExactFractionalClockEdges, TestValidatorAppliesConfiguredClockSkewToAllNumericDates, TestValidatorAcceptsEpochAuthenticationTime |
| [OIDC-DEC-008](../docs/specification-decisions.md) | oidc-core-source | TestValidatorUsesNonceCallback, TestValidatorValidatesAllClaimsBeforeConsumingNonce, TestValidatorAllowsExactlyOneConcurrentNonceConsumption, TestValidatorContainsNonceCallbackPanic, TestValidatorPreservesNonceCancellationAsUnavailable |
| [OIDC-DEC-009](../docs/specification-decisions.md) | oidc-core-source | TestValidateIDTokenBindsAccessTokenAndAuthorizationCode, TestTokenHashAlgorithmsAndMalformedHeaders |
| [OIDC-DEC-010](../docs/specification-decisions.md) | rfc9111-source, oidc-discovery-source, rfc7517-source | TestDiscoveryMetadataAndKeysRefreshTogether, TestDiscoveryValidatorRotatesKeysAndFailsClosedWhenCacheExpiresDuringOutage, TestRemoteKeySetRefreshesRotationMissBeforeCacheExpiry, TestRemoteKeySetRejectsRetiredKeyRollback, TestRemoteRefreshJitterSpreadsReplicaFleet |
| [OIDC-DEC-011](../docs/specification-decisions.md) | rfc9110-source | TestRemoteKeySetSynchronizesLargeRefreshBurst, TestRemoteKeySetBoundsRefreshWaiters, TestRemoteKeySetCancellationDoesNotPoisonSharedRefresh, TestRemoteKeySetRefreshWaitHonorsCancellation, TestRemoteClockRunsOutsideSynchronization, TestConcurrentOIDCAuthenticationAndRotationAreRaceSafe |
| [OIDC-DEC-012](../docs/specification-decisions.md) | oidc-core-source, oidc-discovery-source | TestNewDoesNotExposeProviderResponseText, TestProviderErrorRedactionPreservesOnlyStableCancellation, TestRemoteRefreshReportRedactsTransportFailure, TestValidatorContainsNonceCallbackPanic, TestValidateBearerRejectsCanceledAndEmptyInput |
| [OIDC-DEC-013](../docs/specification-decisions.md) | oidc-discovery-source, oidc-core-source | TestNewPreservesDiscoveryDeadlineAndRejectsIssuerMismatch, TestValidatorRequiresExactIssuerDespiteUpstreamCompatibilityAliases, TestKeycloakProviderIssuedIDToken |
| [OIDC-DEC-014](../docs/specification-decisions.md) | oidc-discovery-source | TestProviderMetadataValidationMatrix, TestGoogleProviderMetadataSnapshot |
| [OIDC-DEC-015](../docs/specification-decisions.md) | oidc-discovery-source | TestRemoteURLValidationRejectsEachUnsafeComponent, TestIssuerURLRequiresBothHTTPOptInAndLoopback, TestHTTPHardeningAndBoundedReaders, TestGoogleProviderMetadataSnapshot |
| [OIDC-DEC-016](../docs/specification-decisions.md) | oidc-core-source | TestJOSEKeyAlgorithmFamilies, TestKeycloakProviderIssuedIDToken |
| [OIDC-DEC-017](../docs/specification-decisions.md) | oidc-core-source | TestValidatorEnforcesOIDCClaimsAndAuthorizedParty, TestValidatorRejectsUntrustedAdditionalAudiences, TestOpenIDConnectCoreIDTokenClaimVector, TestKeycloakProviderIssuedIDToken |
| [OIDC-DEC-018](../docs/specification-decisions.md) | oidc-core-source | TestValidatorEnforcesOIDCClaimsAndAuthorizedParty |
| [OIDC-DEC-019](../docs/specification-decisions.md) | oidc-core-source | TestValidatorUsesNonceCallback, TestValidatorValidatesAllClaimsBeforeConsumingNonce, TestValidatorAllowsExactlyOneConcurrentNonceConsumption |
| [OIDC-DEC-020](../docs/specification-decisions.md) | oidc-core-source | TestValidateIDTokenBindsAccessTokenAndAuthorizationCode, TestTokenHashAlgorithmsAndMalformedHeaders |
| [OIDC-DEC-021](../docs/specification-decisions.md) | oidc-discovery-source | TestProviderMetadataValidationMatrix, TestGoogleProviderMetadataSnapshot, TestKeycloakProviderIssuedIDToken |

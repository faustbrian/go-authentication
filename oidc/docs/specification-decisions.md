# OpenID Connect specification decisions

This register records observable choices where OpenID Connect, JOSE, JSON,
HTTP, or package-owned defensive policy permits more than one implementation.
The final OpenID Connect Core 1.0 and Discovery 1.0 publications incorporating
errata set 2 remain authoritative. Pinned fixtures and provider evidence are
documented in [`../specification/`](../specification/README.md).

## Authority review history

| Reviewed | Authority movement | Monitoring digest | Disposition | Decision impact |
| --- | --- | --- | --- | --- |
| 2026-09-03 | RFC 9110 gained reported technical Erratum 9162 for Section 5.2, proposing that combined field-line values explicitly use a comma followed by a space. | `rfc9110-errata`: `38bd006c96f8963d58573f704c5313a5f81968b90738c03ade0b036ec7bbdf4b` to `1f6790054c0cdb2f2a70a94fa2b9c73b09a4ee0578a32b4a3006ed0ecfaac86d`. | Behavior-neutral. The erratum is reported, not verified, and does not alter the module's synchronous, bounded remote-refresh lifecycle. | `OIDC-DEC-011`, its conformance binding, and runtime behavior remain unchanged. |

## OIDC-DEC-001: Discovery is derived from and bound to one exact issuer

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Sections 4 and 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) and OpenID Connect Core 1.0 [Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | Normative issuer matching plus discovery-path interpretation |
| Issue | Discovery defines an append rule for issuers with paths, while URL normalization and upstream verifier compatibility can otherwise treat case, ports, paths, or trailing slashes as aliases. |
| Credible interpretations | Normalize equivalent URLs; accept provider aliases; use a caller-supplied discovery URL; or derive the well-known URL from one configured issuer and require exact returned and token issuer strings. |
| Known peer behavior | Providers expose the standard well-known document, but libraries and deployments differ in URL normalization and issuer-alias tolerance. |
| Selected behavior | Derive `/.well-known/openid-configuration` using the Discovery append rule. Reject configured issuer query, fragment, userinfo, unsupported schemes, and non-loopback HTTP. The configured issuer, metadata `issuer`, and token `iss` must match byte for byte. |
| Security and resource consequences | Exact binding prevents cross-tenant metadata and token substitution. Discovery performs one bounded initialization request rather than following caller- or token-selected locations. |
| Compatibility and wire consequences | Standard exact issuers, including path issuers, interoperate. Alias, normalization, and trailing-slash differences accepted by permissive peers are intentionally rejected. |
| Executable evidence | `TestNewPreservesDiscoveryDeadlineAndRejectsIssuerMismatch`, `TestValidatorRequiresExactIssuerDespiteUpstreamCompatibilityAliases`, `TestConfigurationRejectsEachInvalidBoundary`, and `FuzzRemoteURL` |
| Public surface | `Config.Issuer`, `New`, `NewWithKeySet`, and `Validator.ValidateIDToken` |
| Upstream record | Discovery errata set 2 defines the issuer append and exact-match requirements; no alias registry is defined. |
| Reconsider when | A future OpenID profile standardizes issuer aliases with downgrade-resistant discovery and token-binding semantics. |

Machine-auditable bindings: classification `ambiguity`; decision scope `defensive`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `not specified`; fuzz evidence `FuzzRemoteURL`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"oidc-core-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-core-1_0.html","specifications":["OpenID Connect Core 1.0 incorporating errata set 2"]}`.

## OIDC-DEC-002: Provider metadata is strict, bounded, and capability-complete

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) and RFC 8259 [Sections 4 and 8.2](https://www.rfc-editor.org/rfc/rfc8259.html#section-4) |
| Classification | Normative metadata validation plus defensive JSON and resource policy |
| Issue | Discovery defines required and optional members but does not settle duplicate JSON names, explicit null for optional members, Unicode whitespace in string lists, or implementation resource ceilings. |
| Credible interpretations | Ignore malformed optional members; accept last duplicate; coerce null to absent; split on all Unicode whitespace; or reject ambiguous standard metadata before key retrieval. |
| Known peer behavior | Real Google, Keycloak, and Dex profiles use conventional unique JSON. General decoders commonly accept duplicate names and null values more permissively. |
| Selected behavior | Require one bounded JSON object and an exact JSON response media type. Standard members must be unique and correctly typed; explicit null is not absence. Response types use one ASCII-space separator, supported subject types are unique, advertised scopes include `openid`, and signing algorithms include RS256 plus every configured algorithm. |
| Security and resource consequences | Strict metadata prevents parser differentials and capability downgrade. Header, body, object, member, collection, key, and initialization bounds apply before retaining provider data. |
| Compatibility and wire consequences | Standards-compliant provider metadata remains unchanged. Malformed-but-tolerated metadata fails construction instead of being silently normalized. |
| Executable evidence | `TestProviderMetadataValidationMatrix`, `TestNewRejectsDuplicateDiscoveryMembersBeforeFetchingKeys`, `TestNewRejectsNullOptionalProviderMetadata`, `TestNewRejectsSigningAlgorithmsNotAdvertisedByProvider`, and `FuzzProviderMetadata` |
| Public surface | `New`, `Config.MaxHTTPBodyBytes`, `Config.DiscoveryTimeout`, `Config.Algorithms`, and `Config.MaxKeys` |
| Upstream record | The OpenID Foundation conformance profiles informed the matrix; they do not replace package-level hostile JSON and allocation policy. |
| Reconsider when | Discovery publishes a new metadata member or erratum requiring a different null, list, or algorithm-advertisement interpretation. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `defensive`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `not specified`; fuzz evidence `FuzzProviderMetadata`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"rfc8259-source","version":"RFC 8259","url":"https://www.rfc-editor.org/rfc/rfc8259.txt","specifications":["RFC 8259 JSON"]}`.

## OIDC-DEC-003: Provider-directed endpoints are HTTPS but may be cross-origin

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Sections 3 and 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse) and RFC 9110 [Section 15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4) |
| Classification | Normative endpoint scheme validation and defensive egress policy |
| Issue | Discovery permits metadata to direct clients to endpoints, including a JWKS origin different from the issuer, but does not define deployment-specific DNS, IP, port, proxy, or redirect trust. |
| Credible interpretations | Require same origin; follow ordinary redirects; permit arbitrary HTTP; embed a global private-network ban; or allow valid HTTPS metadata while delegating topology policy to an injected transport. |
| Known peer behavior | Google's issuer and JWKS use different HTTPS origins. Default Go HTTP clients follow redirects unless explicitly hardened. |
| Selected behavior | Accept valid HTTPS provider endpoints, including cross-origin JWKS. Reject redirects, userinfo, fragments, unsupported schemes, and non-loopback HTTP. `InsecureHTTP` permits loopback development only. Deployments needing DNS, address, port, proxy, or origin restrictions must supply a hardened `HTTPClient` transport. |
| Security and resource consequences | Redirect denial prevents authority changes after validation. Provider-directed egress remains an explicit trust consequence, while caller transport policy can enforce deployment topology without breaking legitimate private or cross-origin issuers. |
| Compatibility and wire consequences | Google-style cross-origin JWKS works. Redirecting and non-loopback plaintext providers are intentionally incompatible; custom transport restrictions may further narrow deployment compatibility. |
| Executable evidence | `TestGoogleProviderMetadataSnapshot`, `TestRemoteURLValidationRejectsEachUnsafeComponent`, `TestHTTPHardeningAndBoundedReaders`, and `TestDiscoveryAndJWKRequestsAreBoundedAndCancelable` |
| Public surface | `Config.HTTPClient`, `Config.InsecureHTTP`, `New`, and provider metadata handling |
| Upstream record | Discovery permits endpoint URLs but does not provide a universal SSRF policy; that deployment boundary remains caller-owned and documented. |
| Reconsider when | Discovery or a deployment profile defines enforceable endpoint-origin constraints compatible with supported providers. |

Machine-auditable bindings: classification `optional behavior`; decision scope `defensive`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `not specified`; fuzz evidence `FuzzRemoteURL`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"rfc9110-source","version":"RFC 9110","url":"https://www.rfc-editor.org/rfc/rfc9110.txt","specifications":["RFC 9110 HTTP Semantics"]}`.

## OIDC-DEC-004: Algorithms and public JWK candidates must agree exactly

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Sections 2 and 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), OpenID Connect Discovery 1.0 [`id_token_signing_alg_values_supported`](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata), RFC 7517 [Sections 4 and 5](https://www.rfc-editor.org/rfc/rfc7517.html#section-4), and RFC 7518 [Section 3](https://www.rfc-editor.org/rfc/rfc7518.html#section-3) |
| Classification | Normative JOSE verification plus defensive key-selection policy |
| Issue | Provider metadata, token `alg`, JWK metadata, key shape, and `kid` can disagree; sets can also contain unrelated encryption keys or ambiguous signing candidates. |
| Credible interpretations | Try every key; infer algorithms from keys; accept HMAC client-secret signatures; reject all unrelated keys; or filter valid public signing candidates and require unambiguous exact agreement. |
| Known peer behavior | General OIDC libraries support configurable algorithms and key sets, with differing treatment of missing IDs and unrelated keys. |
| Selected behavior | Support configured asymmetric RS, PS, ES, and EdDSA families only when advertised by the provider. Candidate keys must be public, algorithm- and shape-compatible, and signing-capable; encryption-only keys are ignored. Ambiguous permitted candidates require `kid`. RSA is 2048 through 8192 bits and EC/EdDSA shape must match exactly. |
| Security and resource consequences | Explicit agreement prevents HMAC/asymmetric confusion and key trial amplification. Key count and RSA upper bounds limit verification work. |
| Compatibility and wire consequences | Supported provider-issued asymmetric tokens interoperate. Symmetric, encrypted, weak, private, ambiguous, or unadvertised tokens and keys are rejected by policy. |
| Executable evidence | `TestJOSEKeyAlgorithmFamilies`, `TestRemoteFetchIgnoresUnrelatedEncryptionKeys`, `TestRemoteFetchRejectsAmbiguousJWKMetadata`, `TestVerifyWithKeysRejectsMissingKeyIDForAmbiguousSet`, and `TestKeycloakProviderIssuedIDToken` |
| Public surface | `Config.Algorithms`, `Config.MaxKeys`, `New`, `NewWithKeySet`, and `Validator.ValidateIDToken` |
| Upstream record | Discovery requires RS256 support and advertises additional algorithms; configuration does not silently inherit the provider's entire algorithm set. |
| Reconsider when | A concrete profile requires encrypted or symmetric ID tokens and can provide separate bounded key and client-secret handling. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `defensive`; specification `RFC 7518 JSON Web Algorithms`; version `RFC 7518`; source authority `rfc7518-source` at `https://www.rfc-editor.org/rfc/rfc7518.txt`; requirement strength `not specified`; fuzz evidence `FuzzJWKSetResponse`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"oidc-core-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-core-1_0.html","specifications":["OpenID Connect Core 1.0 incorporating errata set 2"]}`, `{"id":"oidc-discovery-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-discovery-1_0.html","specifications":["OpenID Connect Discovery 1.0 incorporating errata set 2"]}`, `{"id":"rfc7517-source","version":"RFC 7517","url":"https://www.rfc-editor.org/rfc/rfc7517.txt","specifications":["RFC 7517 JSON Web Key"]}`.

## OIDC-DEC-005: Compact token JSON is inspected before upstream verification

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Section 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), RFC 7515 [Sections 3.1 and 5.2](https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1), RFC 8259 [Sections 4, 6, and 8.2](https://www.rfc-editor.org/rfc/rfc8259.html#section-4) |
| Classification | JOSE serialization support and defensive JSON interoperability policy |
| Issue | Upstream parsers can accept duplicate members, malformed Unicode replacement, excessive nesting, padded encodings, or lossy numeric decoding differently. |
| Credible interpretations | Delegate all parsing; keep first or last duplicate; coerce numbers through float64; support JSON JOSE serialization; or enforce one strict bounded compact representation first. |
| Known peer behavior | Core providers issue compact signed ID tokens, while generic JSON and JOSE parser edge behavior differs. |
| Selected behavior | Require three non-empty strict unpadded base64url segments within `MaxTokenBytes`. Protected header and claims are bounded unique-member JSON objects with valid Unicode and correctly typed standard members. Claims are decoded losslessly without float64 coercion. Unsupported distributed-claim protocol fields are rejected. |
| Security and resource consequences | Parser differential, duplicate-key smuggling, number precision loss, nested allocation, and malformed Unicode fail before trust or principal construction. |
| Compatibility and wire consequences | Conventional compact provider tokens remain compatible. Permissive or non-compact encodings are rejected rather than normalized. Private JSON numbers preserve exact lexical value in the principal. |
| Executable evidence | `TestValidatorRejectsMalformedBoundedAndDuplicateTokens`, `TestInspectCompactTokenRejectsEachBoundary`, `TestValidatorRejectsClaimsThatCannotBeDecodedLosslessly`, `TestValidatorPreservesPrivateNumbersAndRejectsInvalidUnicode`, and `FuzzInspectCompactToken` |
| Public surface | `Config.MaxTokenBytes`, `Config.MaxClaims`, `Config.MaxClaimDepth`, and `Validator.ValidateIDToken` |
| Upstream record | No erratum mandates permissive duplicate or lossy-number behavior; strict parsing is package-owned hardening. |
| Reconsider when | Core adopts another mandatory ID-token serialization with equivalent deterministic and bounded parsing rules. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `defensive`; specification `RFC 7515 JSON Web Signature`; version `RFC 7515`; source authority `rfc7515-source` at `https://www.rfc-editor.org/rfc/rfc7515.txt`; requirement strength `not specified`; fuzz evidence `FuzzInspectCompactToken`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"oidc-core-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-core-1_0.html","specifications":["OpenID Connect Core 1.0 incorporating errata set 2"]}`, `{"id":"rfc8259-source","version":"RFC 8259","url":"https://www.rfc-editor.org/rfc/rfc8259.txt","specifications":["RFC 8259 JSON"]}`.

## OIDC-DEC-006: Audience, authorized party, and subject form one principal boundary

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Sections 2 and 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | Normative audience and authorized-party validation plus defensive subject profile |
| Issue | Core permits multiple audiences and optional `azp` in some cases, while applications need to prevent trusted-client tokens from carrying arbitrary additional recipients or malformed subjects. |
| Credible interpretations | Check only that client ID appears; accept any extra audience; ignore `azp`; normalize subject text; or require an explicit complete recipient and subject policy. |
| Known peer behavior | OIDC libraries commonly check client membership but may not reject additional audiences unless callers add policy. |
| Selected behavior | Require client ID in a unique audience set. Every extra audience must be explicitly trusted. `azp`, when present, equals client ID and is mandatory for multiple audiences. Subject is non-empty ASCII and at most 255 bytes. Exact issuer and subject become the principal identity. |
| Security and resource consequences | Prevents cross-client token reuse and ambiguous principal identifiers. Audience and subject sizes remain bounded before principal allocation. |
| Compatibility and wire consequences | Single-client and explicitly trusted multi-audience tokens work. Tokens with duplicate or untrusted audiences, wrong or missing required `azp`, Unicode subjects, or oversized subjects are rejected. |
| Executable evidence | `TestValidatorEnforcesOIDCClaimsAndAuthorizedParty`, `TestValidatorRejectsUntrustedAdditionalAudiences`, `TestValidatorRejectsNonASCIIOrOversizedSubject`, and `TestOpenIDConnectCoreIDTokenClaimVector` |
| Public surface | `Config.ClientID`, `Config.TrustedAudiences`, `Validator.ValidateIDToken`, and `authentication.Principal` |
| Upstream record | Core defines audience and `azp`; rejection of unlisted additional audiences and the subject byte profile are explicit application hardening. |
| Reconsider when | A deployment needs another subject syntax or audience delegation model with an explicit non-ambiguous principal mapping. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `defensive`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `not specified`; fuzz evidence `FuzzValidateBearer`; fixture evidence `oidc/testdata/oidc-core-section-2-claims.json`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.

## OIDC-DEC-007: NumericDate validation preserves fractions and one skew policy

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Sections 2 and 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) and RFC 7519 [`NumericDate`](https://www.rfc-editor.org/rfc/rfc7519.html#section-2) |
| Classification | NumericDate precision and boundary interpretation |
| Issue | NumericDate permits non-integer values, libraries can truncate fractions, and Core permits implementation-specific clock skew without defining every equality edge. |
| Credible interpretations | Truncate to seconds; use wall clock repeatedly; ignore `iat`; configure independent leeway; or preserve exact fractions against one injected clock and symmetric skew. |
| Known peer behavior | OIDC and JWT libraries differ in fractional parsing and optional claim checks. |
| Selected behavior | Require `iat` and `exp`; validate optional `nbf` and `auth_time`; preserve fractional seconds; read the configured clock deterministically; and apply one bounded non-negative `ClockSkew` to every temporal boundary. Epoch `auth_time` is valid. |
| Security and resource consequences | Exact comparisons avoid truncation acceptance windows. Explicit skew bounds replay tolerance and makes tests deterministic. |
| Compatibility and wire consequences | Integer and fractional NumericDate values interoperate. Tokens accepted only because a peer truncates fractions or ignores a temporal claim are deliberately rejected. |
| Executable evidence | `TestNumericDateBoundariesAndFraction`, `TestValidatorAppliesExactFractionalClockEdges`, `TestValidatorAppliesConfiguredClockSkewToAllNumericDates`, `TestValidatorAcceptsEpochAuthenticationTime`, and `FuzzNumericDate` |
| Public surface | `Config.Clock`, `Config.ClockSkew`, `Validator.ValidateIDToken`, and principal authentication time |
| Upstream record | Core permits reasonable skew but does not define its amount; the package's default and upper bound are explicit implementation policy. |
| Reconsider when | A profile mandates per-claim leeway or higher-precision time semantics. |

Machine-auditable bindings: classification `implementation-defined behavior`; decision scope `defensive`; specification `RFC 7519 JSON Web Token`; version `RFC 7519`; source authority `rfc7519-source` at `https://www.rfc-editor.org/rfc/rfc7519.txt`; requirement strength `MAY`; fuzz evidence `FuzzNumericDate`; fixture evidence `oidc/testdata/oidc-core-section-2-claims.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"oidc-core-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-core-1_0.html","specifications":["OpenID Connect Core 1.0 incorporating errata set 2"]}`.

## OIDC-DEC-008: Nonce replay ownership stays with one caller callback

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Sections 3.1.2.1 and 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) |
| Classification | Application-owned nonce replay and callback policy layered on Core nonce comparison |
| Issue | Core requires nonce comparison when sent but cannot define application storage, atomic consumption, expiry, replay coordination, or callback failure handling. |
| Credible interpretations | Store nonce in the package; compare a caller string; make checking optional even when configured; invoke before other validation; or delegate atomic single-use consumption after all other checks. |
| Known peer behavior | OIDC libraries commonly return nonce for callers to compare. Replay stores remain application-specific. |
| Selected behavior | `NonceValidator` owns presence, expiry, equality, and atomic single-use consumption. Invoke it once only after signature, binding, and every other claim succeeds. Contain callback panic and redact callback errors as rejection; preserve callback context cancellation as authentication unavailability. |
| Security and resource consequences | Invalid tokens cannot consume valid nonce state, and concurrent replay races are resolved by the caller's atomic store. The package retains no nonce or replay database. |
| Compatibility and wire consequences | Token bytes are unchanged. Applications enabling nonce validation must provide a concurrency-safe consuming callback; omission leaves nonce policy caller-owned. |
| Executable evidence | `TestValidatorUsesNonceCallback`, `TestValidatorValidatesAllClaimsBeforeConsumingNonce`, `TestValidatorAllowsExactlyOneConcurrentNonceConsumption`, `TestValidatorContainsNonceCallbackPanic`, and `TestValidatorPreservesNonceCancellationAsUnavailable` |
| Public surface | `Config.NonceValidator`, `NonceValidator`, `NonceValidatorFunc`, and `Validator.ValidateIDToken` |
| Upstream record | Core owns nonce semantics; storage and atomic replay prevention are deliberately outside the protocol package. |
| Reconsider when | A reusable nonce-store adapter can be added without embedding persistence or weakening caller lifecycle ownership. |

Machine-auditable bindings: classification `implementation-defined behavior`; decision scope `application-policy`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `not specified`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this application boundary optional or undefined, so the package records a stable caller-facing policy without presenting it as specification-mandated.

## OIDC-DEC-009: Front-channel token hashes are validated only from explicit call inputs

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [`at_hash`](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken) and [`c_hash`](https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2) validation rules |
| Classification | Flow-specific normative validation and explicit API policy |
| Issue | Whether `at_hash` or `c_hash` is required depends on authorization flow and returned values that cannot be inferred from the ID token alone. EdDSA also names no hash family for OIDC half-hash selection. |
| Credible interpretations | Ignore both claims; infer the flow; require both universally; accept claims without caller values; or validate each only when its opaque source value is supplied explicitly. |
| Known peer behavior | OIDC clients often perform these checks in flow-specific code rather than generic bearer validation. |
| Selected behavior | `ValidateIDToken` validates `at_hash` for non-empty access-token input and `c_hash` for non-empty authorization-code input using the signing algorithm's 256/384/512 hash family. A requested binding requires the claim and exact value. EdDSA with requested binding is rejected because no hash family is defined. `ValidateBearer` supplies no front-channel values. |
| Security and resource consequences | Explicit inputs prevent false assurance from an inferred flow and bind returned artifacts against substitution. Hash work is bounded by caller-supplied token/code length and call lifetime. |
| Compatibility and wire consequences | Correct code, implicit, and hybrid responses interoperate when callers provide their returned values. Callers omitting those inputs do not receive a claim of front-channel binding. |
| Executable evidence | `TestValidateIDTokenBindsAccessTokenAndAuthorizationCode` and `TestTokenHashAlgorithmsAndMalformedHeaders` |
| Public surface | `TokenBinding`, `Validator.ValidateIDToken`, and `Validator.ValidateBearer` |
| Upstream record | Core defines flow-specific requirements; this API exposes rather than guesses the missing flow context. |
| Reconsider when | A higher-level authorization-flow package can guarantee and supply these values automatically without changing this validator's narrow boundary. |

Machine-auditable bindings: classification `optional behavior`; decision scope `application-policy`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `not specified`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this application boundary optional or undefined, so the package records a stable caller-facing policy without presenting it as specification-mandated.

## OIDC-DEC-010: Metadata and JWKS refresh together, expire fail closed, and reject rollback

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Section 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse), RFC 9111 [Sections 4.2 and 5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2), and RFC 7517 [Section 5](https://www.rfc-editor.org/rfc/rfc7517.html#section-5) |
| Classification | HTTP freshness interpretation and defensive rotation policy |
| Issue | OIDC does not define refresh synchronization, unknown-key probes, stale-key outage behavior, metadata/JWKS atomicity, or rollback after a key is retired. |
| Credible interpretations | Cache forever; serve stale during outage; refetch on every unknown ID; refresh only keys; accept provider rollback; or maintain one bounded fail-closed state transition. |
| Known peer behavior | Remote key caches commonly retry unknown IDs and serve cached keys, but cooldown, expiry, metadata changes, and rollback behavior differ. |
| Selected behavior | Refresh metadata and JWKS as one synchronized transition. Clamp HTTP freshness to configured bounds and apply per-instance early jitter. After cooldown, an unknown `kid` triggers one shared probe. Known keys work only while fresh; required refresh failure is cached until the minimum interval and fails closed after expiry. Successful removal retires key material for this validator lifetime; later rollback cannot reintroduce it. A changed `jwks_uri` clears validators for the old URL. |
| Security and resource consequences | Cooldown and synchronization prevent attacker-driven request storms. Fail-closed expiry and bounded retired-key history prevent indefinite stale trust and rollback within one process, at the cost of availability during provider outage. |
| Compatibility and wire consequences | Normal provider rotation works before or at freshness expiry. Reintroducing retired key material or relying on stale keys after expiry is intentionally incompatible. Reconstructing a validator resets process-local retirement history. |
| Executable evidence | `TestDiscoveryMetadataAndKeysRefreshTogether`, `TestDiscoveryValidatorRotatesKeysAndFailsClosedWhenCacheExpiresDuringOutage`, `TestRemoteKeySetRefreshesRotationMissBeforeCacheExpiry`, `TestRemoteKeySetRejectsRetiredKeyRollback`, and `TestRemoteRefreshJitterSpreadsReplicaFleet` |
| Public surface | `Config.MinRefreshInterval`, `Config.MaxRefreshInterval`, `Config.MaxRefreshWaiters`, `New`, and remote signature verification |
| Upstream record | HTTP controls freshness, but fail-closed expiry and retired-key rollback prevention are explicit package security policy. |
| Reconsider when | A provider profile supplies authenticated push invalidation or a shared cache protocol with equivalent bounded rollback protection. |

Machine-auditable bindings: classification `implementation-defined behavior`; decision scope `defensive`; specification `RFC 9111 HTTP Caching`; version `RFC 9111`; source authority `rfc9111-source` at `https://www.rfc-editor.org/rfc/rfc9111.txt`; requirement strength `not specified`; fuzz evidence `FuzzJWKSetResponse`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"oidc-discovery-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-discovery-1_0.html","specifications":["OpenID Connect Discovery 1.0 incorporating errata set 2"]}`, `{"id":"rfc7517-source","version":"RFC 7517","url":"https://www.rfc-editor.org/rfc/rfc7517.txt","specifications":["RFC 7517 JSON Web Key"]}`.

## OIDC-DEC-011: Refresh concurrency is synchronous, bounded, and caller-cancelable

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | Go's [`context` contract](https://pkg.go.dev/context) and RFC 9110 [Section 9.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2) |
| Classification | Implementation-defined concurrency, cancellation, and lifecycle policy |
| Issue | Protocol specifications do not define which caller owns refresh, how waiters cancel, whether refresh starts goroutines, or how one cancellation affects shared state. |
| Credible interpretations | Spawn background refresh; let every caller fetch; allow unbounded waiters; let owner cancellation poison cooldown; or use one synchronous owner with bounded independent waiters. |
| Known peer behavior | Cache libraries use background refresh, singleflight, or per-request retrieval with materially different lifecycle behavior. |
| Selected behavior | The validator starts no goroutines or timers. One caller synchronously owns each network refresh; admitted waiters are bounded and retain independent contexts. Owner cancellation does not poison another caller's future refresh or shared cooldown. Clock callbacks run outside synchronization. Every response body is closed. |
| Security and resource consequences | `MaxRefreshWaiters`, request deadlines, body limits, and one owner bound memory, goroutines, sockets, and upstream load. No `Close` method is required because no package-owned background lifetime exists. |
| Compatibility and wire consequences | No OIDC wire change. Validation may return unavailable under waiter saturation or cancellation rather than queue indefinitely. Caller collaborators must honor context and be concurrency-safe. |
| Executable evidence | `TestRemoteKeySetSynchronizesLargeRefreshBurst`, `TestRemoteKeySetBoundsRefreshWaiters`, `TestRemoteKeySetCancellationDoesNotPoisonSharedRefresh`, `TestRemoteKeySetRefreshWaitHonorsCancellation`, `TestRemoteClockRunsOutsideSynchronization`, and `TestConcurrentOIDCAuthenticationAndRotationAreRaceSafe` |
| Public surface | `Config.MaxRefreshWaiters`, `Config.HTTPClient`, `Config.Clock`, `New`, and validation contexts |
| Upstream record | This is a Go runtime contract layered over protocol messages; no OpenID erratum defines process lifecycle. |
| Reconsider when | A background refresh design can prove explicit close ownership, equivalent bounds, and no weaker cancellation or fleet behavior. |

Machine-auditable bindings: classification `implementation-defined behavior`; decision scope `defensive`; specification `RFC 9110 HTTP Semantics`; version `RFC 9110`; source authority `rfc9110-source` at `https://www.rfc-editor.org/rfc/rfc9110.txt`; requirement strength `not specified`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.

## OIDC-DEC-012: Errors are stable, redacted, and preserve only safe cancellation identity

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) and OpenID Connect Discovery 1.0 [Section 4.4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation) |
| Classification | Defensive diagnostics and application error-policy decision |
| Issue | Callers need invalid, rejected, and unavailable distinctions, but provider, callback, token, nonce, key, credential, and response errors can retain secrets or create a validation oracle. |
| Credible interpretations | Return upstream causes verbatim; expose provider bodies; collapse every error; retain all wrapped causes; or map to stable categories while preserving only context cancellation identity. |
| Known peer behavior | OIDC libraries expose detailed verifier and HTTP errors useful for tooling but unsafe to return or log directly at an authentication boundary. |
| Selected behavior | Empty, wrong-kind, malformed, or oversized credentials are invalid; signature, issuer, claim, nonce, and binding failures are rejected; discovery, JWKS, rollback, timeout, waiter saturation, and cancellation are unavailable. Public errors do not retain arbitrary provider, callback, token, nonce, key, credential, or body text. Safe `context.Canceled` and deadline identity remains detectable. |
| Security and resource consequences | Redaction prevents secret-bearing errors and low-cardinality categories avoid attacker-controlled telemetry. Operators retain enough classification for retry and availability policy. |
| Compatibility and wire consequences | Adapters receive stable authentication categories rather than provider-specific diagnostics. Consumers must use `errors.Is` and `errors.As`, not compare messages or expect raw causes. |
| Executable evidence | `TestNewDoesNotExposeProviderResponseText`, `TestProviderErrorRedactionPreservesOnlyStableCancellation`, `TestRemoteRefreshReportRedactsTransportFailure`, `TestValidatorContainsNonceCallbackPanic`, and `TestValidateBearerRejectsCanceledAndEmptyInput` |
| Public surface | `New`, `Validator.Authenticate`, `Validator.ValidateBearer`, `Validator.ValidateIDToken`, and `authentication.Failure` |
| Upstream record | OpenID defines validation outcomes but not Go error-chain disclosure; this redaction profile is package-owned. |
| Reconsider when | A protocol adapter requires a standardized external error code that can map from these categories without retaining sensitive detail. |

Machine-auditable bindings: classification `omission`; decision scope `defensive`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `not specified`; fuzz evidence `FuzzValidateBearer`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The cited authority leaves this boundary ambiguous or incomplete, so the selected fail-closed behavior is documented as package hardening rather than a specification requirement.
Additional authoritative sources: `{"id":"oidc-discovery-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-discovery-1_0.html","specifications":["OpenID Connect Discovery 1.0 incorporating errata set 2"]}`.

## OIDC-DEC-013: Provider metadata and ID Tokens use the exact configured issuer

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Section 4.3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation) and OpenID Connect Core 1.0 [Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | interoperability policy |
| Issue | Issuer aliases and URL normalization can bind provider metadata or tokens to a different tenant or trust domain than the issuer selected by the client. |
| Credible interpretations | Normalize equivalent URLs; accept provider aliases; or require byte-for-byte identity between the configured issuer, discovered metadata issuer, and token issuer. |
| Known peer behavior | Observed providers preserve exact issuer identity, while some libraries accept compatibility aliases or normalized URL forms. |
| Selected behavior | The configured issuer, the discovered metadata `issuer`, and the ID Token `iss` claim must match exactly. Alias, case, port, path, and trailing-slash differences are rejected. |
| Security and resource consequences | Security: Exact identity prevents metadata, key, and token substitution across issuer aliases or tenants. Resource: Issuer comparison is bounded by the configured metadata and token limits. |
| Compatibility and wire consequences | Compatibility: Providers and clients must use one exact issuer identifier across configuration, discovery, and tokens. Wire: A metadata document or ID Token with a non-identical issuer is rejected. |
| Executable evidence | `TestNewPreservesDiscoveryDeadlineAndRejectsIssuerMismatch`, `TestValidatorRequiresExactIssuerDespiteUpstreamCompatibilityAliases`, `TestKeycloakProviderIssuedIDToken` |
| Public surface | `Config.Issuer`, `New`, `NewWithKeySet`, and `Validator.ValidateIDToken` |
| Upstream record | Discovery Section 4.3 and Core Section 3.1.3.7 require exact issuer identity. |
| Reconsider when | A future OpenID profile replaces exact issuer identity with an authenticated alias mechanism. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `MUST`; fuzz evidence `FuzzRemoteURL`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This preserves Discovery and Core's exact issuer-match requirements separately from URL construction and defensive URL-policy choices.
Additional authoritative sources: `{"id":"oidc-core-source","version":"final-errata-2","url":"https://openid.net/specs/openid-connect-core-1_0.html","specifications":["OpenID Connect Core 1.0 incorporating errata set 2"]}`.

## OIDC-DEC-014: Discovery metadata contains every required provider member

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) |
| Classification | interoperability policy |
| Issue | A Discovery response without the required provider metadata cannot establish the issuer, authorization endpoint, signing keys, response types, subject types, and ID Token signing algorithms needed by an OpenID client. |
| Credible interpretations | Infer omitted defaults; accept a partial metadata profile; or reject a response missing any required Discovery member. |
| Known peer behavior | The pinned Google metadata and representative provider profiles include the required members. |
| Selected behavior | Provider metadata must contain non-null, correctly typed `issuer`, `authorization_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, and `id_token_signing_alg_values_supported` members. |
| Security and resource consequences | Security: The client never infers a trust endpoint, key location, subject model, or signing capability from missing metadata. Resource: Required-member validation runs within the bounded metadata object before JWKS retrieval. |
| Compatibility and wire consequences | Compatibility: Partial or null-filled provider metadata is rejected even when a permissive client could infer defaults. Wire: A Discovery response missing any required member is invalid. |
| Executable evidence | `TestProviderMetadataValidationMatrix`, `TestGoogleProviderMetadataSnapshot` |
| Public surface | `New` and provider metadata validation |
| Upstream record | Discovery Section 3 marks these six provider metadata members REQUIRED. |
| Reconsider when | A later Discovery version changes the required provider metadata set. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `REQUIRED`; fuzz evidence `FuzzProviderMetadata`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This records Discovery's REQUIRED members without upgrading separately recommended or optional metadata to mandatory status.

## OIDC-DEC-015: Provider authorization and JWKS endpoints use HTTPS

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) |
| Classification | interoperability policy |
| Issue | Provider-directed authorization and key endpoints cross a network trust boundary and Discovery requires them to use HTTPS. |
| Credible interpretations | Accept any URL scheme; follow provider redirects; or require direct HTTPS endpoints while exposing loopback HTTP only as an explicit non-conformant development extension. |
| Known peer behavior | The pinned Google and Keycloak provider profiles publish HTTPS endpoints in conformant deployment metadata. |
| Selected behavior | Provider `authorization_endpoint` and `jwks_uri` values must use HTTPS. Plain HTTP is rejected except for the explicit loopback-only `InsecureHTTP` development extension, which is outside the conformance claim. |
| Security and resource consequences | Security: Production metadata cannot downgrade authorization or signing-key retrieval to unauthenticated transport. Resource: URL validation occurs before any network request; redirect and response bounds remain governed separately. |
| Compatibility and wire consequences | Compatibility: Production providers must publish direct HTTPS endpoints. Loopback HTTP remains available only through explicit development configuration. Wire: Non-HTTPS production endpoint metadata is rejected. |
| Executable evidence | `TestRemoteURLValidationRejectsEachUnsafeComponent`, `TestIssuerURLRequiresBothHTTPOptInAndLoopback`, `TestHTTPHardeningAndBoundedReaders`, `TestGoogleProviderMetadataSnapshot` |
| Public surface | `Config.InsecureHTTP`, `New`, and provider endpoint validation |
| Upstream record | Discovery Section 3 requires HTTPS for the authorization and JWKS endpoint URLs. |
| Reconsider when | A successor Discovery specification defines another authenticated endpoint transport. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `MUST`; fuzz evidence `FuzzRemoteURL`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This preserves Discovery's HTTPS requirements while clearly excluding the explicit loopback development extension from protocol conformance.

## OIDC-DEC-016: ID Token signatures use their declared algorithm and issuer key

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Sections 3.1.3.7 and 3.2.2.11](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | interoperability policy |
| Issue | An ID Token signature must be validated with the algorithm selected for the response and keys belonging to the exact issuer. |
| Credible interpretations | Trust any library-supported algorithm and compatible key; accept an unadvertised algorithm; or require an advertised configured algorithm and a matching public issuer key. |
| Known peer behavior | The pinned Keycloak provider issues an RS256 ID Token that validates against its advertised public JWKS. |
| Selected behavior | ID Token signatures must validate using the algorithm specified by the protected `alg` header and keys provided by the exact issuer. |
| Security and resource consequences | Security: Tokens cannot authenticate through an algorithm different from the protected `alg` header or trust material from another issuer. Resource: Candidate algorithm and key work remains bounded by configured algorithm and JWKS limits. |
| Compatibility and wire consequences | Compatibility: The token's declared algorithm and a compatible public issuer key must produce a valid signature. Wire: ID Tokens with unverifiable signatures, algorithm-operation disagreement, or no matching issuer key are rejected. |
| Executable evidence | `TestJOSEKeyAlgorithmFamilies`, `TestKeycloakProviderIssuedIDToken` |
| Public surface | `Config.Algorithms`, `New`, `NewWithKeySet`, and ID Token validation |
| Upstream record | Core requires clients to validate ID Token signatures using the selected JOSE algorithm and issuer keys. |
| Reconsider when | A future OpenID profile changes the mandatory ID Token signature-validation mechanism. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `MUST`; fuzz evidence `FuzzJWKSetResponse`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This preserves Core's mandatory signature validation separately from the package's narrower key-size, key-selection, and supported-algorithm policy.

## OIDC-DEC-017: The ID Token audience contains the client ID and no untrusted audience

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | interoperability policy |
| Issue | Signature validity does not prove that an ID Token was issued for this client; the client must be one of the token audiences. |
| Credible interpretations | Accept any signed audience; infer the audience from `azp`; or require the configured client ID in the `aud` claim and reject untrusted additional audiences. |
| Known peer behavior | The official Core claims vector and provider-issued token bind the audience to the client identifier. |
| Selected behavior | The ID Token `aud` claim must contain the configured client ID, every additional audience must be trusted explicitly, and the token is rejected otherwise. Separate `azp` policy remains recorded in OIDC-DEC-006 and OIDC-DEC-018. |
| Security and resource consequences | Security: Tokens issued only for another client or carrying an untrusted additional audience cannot authenticate at this client boundary. Resource: Audience parsing and comparison remain bounded by the configured claim limits. |
| Compatibility and wire consequences | Compatibility: Every accepted token must identify the configured client ID and no untrusted recipient in its audience set. Wire: ID Tokens omitting the configured client ID or containing an untrusted additional audience are rejected. |
| Executable evidence | `TestValidatorEnforcesOIDCClaimsAndAuthorizedParty`, `TestValidatorRejectsUntrustedAdditionalAudiences`, `TestOpenIDConnectCoreIDTokenClaimVector`, `TestKeycloakProviderIssuedIDToken` |
| Public surface | `Config.ClientID`, `Config.TrustedAudiences`, and ID Token validation |
| Upstream record | Core Section 3.1.3.7 requires the audience to contain the client's registered client ID. |
| Reconsider when | A future OpenID profile replaces client ID audience binding with another mandatory recipient-binding mechanism. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `MUST`; fuzz evidence `FuzzValidateBearer`; fixture evidence `oidc/testdata/oidc-core-section-2-claims.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This preserves Core's mandatory client-audience and trusted-additional-audience checks without upgrading its separate `azp` recommendations.

## OIDC-DEC-018: A present authorized-party claim identifies this client

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Section 3.1.3.7, items 4 and 5](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | interoperability policy |
| Issue | When an extension supplies `azp`, the client should validate the authorized party instead of ignoring a claim that can disambiguate the token recipient. |
| Credible interpretations | Ignore `azp`; validate it only under an extension-specific profile; or require a present `azp` to equal the configured client ID. |
| Known peer behavior | Provider and client libraries vary because Core makes authorized-party validation extension-aware and recommended rather than universally mandatory. |
| Selected behavior | When `azp` is present, it must be a non-empty string equal to the configured client ID. The package's stricter requirement for `azp` with multiple audiences remains defensive policy in OIDC-DEC-006. |
| Security and resource consequences | Security: A present authorized-party claim cannot identify a different client without rejection. Resource: The bounded claim is compared once to the configured client ID. |
| Compatibility and wire consequences | Compatibility: Tokens with a present `azp` naming another party are rejected; absence is governed separately by the multi-audience defensive profile. Wire: A present `azp` must equal the configured client ID. |
| Executable evidence | `TestValidatorEnforcesOIDCClaimsAndAuthorizedParty` |
| Public surface | `Config.ClientID` and ID Token validation |
| Upstream record | Core recommends extension-aware `azp` validation and says clients should verify a present value against their client ID. |
| Reconsider when | A supported extension profile defines a different authorized-party validation rule. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `recommended`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `SHOULD`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This preserves Core's recommendation without upgrading the source to a universal MUST or claiming that Core requires `azp` for every multi-audience token.

## OIDC-DEC-019: A sent nonce is present and matches exactly

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) |
| Classification | interoperability policy |
| Issue | When an authentication request sent a nonce, accepting an ID Token without the same nonce breaks the request-to-token binding. |
| Credible interpretations | Ignore nonce; accept absence; normalize nonce values; or require presence and exact equality to the value sent in the authentication request. |
| Known peer behavior | OIDC clients commonly expose nonce validation hooks, but callback ownership and replay storage differ. |
| Selected behavior | When a caller supplies a nonce validation contract for a sent nonce, the ID Token must contain the nonce and its value must match exactly. Missing or mismatched nonce is rejected. |
| Security and resource consequences | Security: The ID Token remains bound to the initiating authentication request and cannot be substituted across nonce contexts. Resource: Nonce validation runs once within existing token and callback bounds. |
| Compatibility and wire consequences | Compatibility: Callers that sent a nonce must supply a validator capable of checking its exact value. Wire: A missing or mismatched nonce claim causes rejection when nonce validation is required. |
| Executable evidence | `TestValidatorUsesNonceCallback`, `TestValidatorValidatesAllClaimsBeforeConsumingNonce`, `TestValidatorAllowsExactlyOneConcurrentNonceConsumption` |
| Public surface | `Config.NonceValidator` and ID Token validation |
| Upstream record | Core Section 3.1.3.7 requires presence and exact checking when a nonce was sent. |
| Reconsider when | A future OpenID profile replaces nonce request binding with another mandatory mechanism. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `MUST`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: This preserves Core's mandatory sent-nonce presence and equality check separately from the package's callback, ordering, cancellation, and replay-storage policy.

## OIDC-DEC-020: Presented front-channel token hashes match exactly

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Core 1.0 [Sections 3.2.2.9 and 3.3.2.10](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation) |
| Classification | interoperability policy |
| Issue | Front-channel access tokens and authorization codes need an exact cryptographic binding to the ID Token when their hash claims are used. |
| Credible interpretations | Trust presence of the hash claim; compare an implementation-defined encoding; or compute the algorithm-defined left-half hash and require exact equality. |
| Known peer behavior | OIDC libraries vary in whether flow context and front-channel values are supplied to low-level ID Token validators. |
| Selected behavior | When `ValidateIDToken` is asked to bind an access token or authorization code, the corresponding `at_hash` or `c_hash` claim must be present and must exactly match the algorithm-defined left-half hash. The API does not infer flow context when no value is supplied. |
| Security and resource consequences | Security: Exact hash binding prevents access-token or authorization-code substitution in the validated front-channel response. Resource: Hash work is bounded by the caller-supplied token/code and supported signing algorithm. |
| Compatibility and wire consequences | Compatibility: A requested binding fails when the corresponding claim is absent, malformed, unsupported, or mismatched. Wire: Presented `at_hash` and `c_hash` claims must match their corresponding values exactly when validation is requested. |
| Executable evidence | `TestValidateIDTokenBindsAccessTokenAndAuthorizationCode`, `TestTokenHashAlgorithmsAndMalformedHeaders` |
| Public surface | `TokenBinding` and `Validator.ValidateIDToken` |
| Upstream record | Core Sections 3.2.2.9 and 3.3.2.10 require present front-channel hash claims to match the algorithm-defined value. |
| Reconsider when | A future OpenID profile replaces these hash bindings or defines additional supported signing-algorithm hash families. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Core 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-core-source` at `https://openid.net/specs/openid-connect-core-1_0.html`; requirement strength `MUST`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: Core requires the claim value to match the computed hash; the package's explicit-input API supplies the otherwise unavailable flow context without claiming the hash is mandatory in every flow.

## OIDC-DEC-021: Discovery advertises the mandatory RS256 baseline

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `authentication/oidc` maintainers |
| Source | OpenID Connect Discovery 1.0 [Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) |
| Classification | interoperability policy |
| Issue | Discovery requires `id_token_signing_alg_values_supported` to include RS256 as the interoperable signing baseline. |
| Credible interpretations | Accept any non-empty algorithm list; accept only caller-configured algorithms; or require RS256 in addition to every configured algorithm. |
| Known peer behavior | The pinned Google metadata and Keycloak provider advertise RS256. |
| Selected behavior | Provider metadata must advertise RS256 in `id_token_signing_alg_values_supported`. |
| Security and resource consequences | Security: The client does not silently accept a provider profile that omits OpenID Connect's mandatory signing baseline. Resource: Algorithm-list validation is bounded by the metadata limits. |
| Compatibility and wire consequences | Compatibility: Providers omitting RS256 are rejected even when another locally supported algorithm overlaps. Wire: Discovery metadata without RS256 in the advertised ID Token signing algorithm list is invalid. |
| Executable evidence | `TestProviderMetadataValidationMatrix`, `TestGoogleProviderMetadataSnapshot`, `TestKeycloakProviderIssuedIDToken` |
| Public surface | `New` and provider metadata validation |
| Upstream record | Discovery Section 3 requires RS256 in the advertised ID Token signing algorithm list. |
| Reconsider when | A later Discovery version replaces RS256 as the mandatory algorithm baseline. |

Machine-auditable bindings: classification `interoperability policy`; decision scope `normative`; specification `OpenID Connect Discovery 1.0 incorporating errata set 2`; version `final-errata-2`; source authority `oidc-discovery-source` at `https://openid.net/specs/openid-connect-discovery-1_0.html`; requirement strength `MUST`; fuzz evidence `FuzzProviderMetadata`; fixture evidence `oidc/testdata/google-openid-configuration-2026-08-09.json`; interoperability evidence `oidc/specification/interoperability.tsv`; documentation `oidc/docs/specification-decisions.md`.
Normative rationale: The RS256 requirement comes directly from Discovery; requiring other configured algorithms remains the package's separate capability-consistency policy.


## Unresolved decisions

None. New OpenID profiles, JOSE algorithms, metadata members, distributed
claims, encrypted tokens, refresh behaviors, or peer divergences MUST be
registered before observable support is selected. An unresolved validation,
security, wire, resource, or lifecycle decision blocks release of the affected
surface.

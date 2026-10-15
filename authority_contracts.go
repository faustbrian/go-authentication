package authentication

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-clock"
)

// AuthorityOwnerKind is a closed owner classification. Empty is invalid;
// credential owner, human actor and calling workload are never interchangeable.
type AuthorityOwnerKind string

const (
	// AuthorityOwnerUnspecified is an invalid credential-owner kind.
	AuthorityOwnerUnspecified AuthorityOwnerKind = ""
	// AuthorityOwnerUser identifies a user-owned credential.
	AuthorityOwnerUser AuthorityOwnerKind = "user"
	// AuthorityOwnerOrganization identifies an organization-owned credential independently of its creator.
	AuthorityOwnerOrganization AuthorityOwnerKind = "organization"
	// AuthorityOwnerWorkload identifies machine-only authority, not customer delegation.
	AuthorityOwnerWorkload AuthorityOwnerKind = "workload"
)

// AuthorityOwner is a non-secret, caller-owned owner/version projection.
// Its zero value is invalid; token validation requires an exact positive version.
type AuthorityOwner struct {
	// Kind selects the closed classification; unknown and zero values are invalid.
	Kind AuthorityOwnerKind `json:"kind"`
	// ID identifies this exact proof or versioned authority node within its owning issuer.
	ID string `json:"id"`
	// Version is the positive authoritative version of this exact identity or dimension.
	Version uint64 `json:"version"`
}

// AuthorityGrant identifies one versioned lineage node. Its zero value is
// invalid. Zero ExpiresAt denotes a non-expiring source, not an unbounded child;
// access tokens still expire within five minutes and every finite ancestor.
type AuthorityGrant struct {
	// ID identifies this exact proof or versioned authority node within its owning issuer.
	ID string `json:"id"`
	// Version is the positive authoritative version of this exact identity or dimension.
	Version uint64 `json:"version"`
	// ExpiresAt is the exclusive expiry; a zero source-grant expiry denotes no source deadline.
	ExpiresAt time.Time `json:"expires_at"`
}

// AccessTokenClaims is the closed shared-issuer-v1 access-token projection.
// Registered times are Unix seconds; expiry is exclusive. All retained fields
// are copied by validation. Zero values are invalid. Owner, optional actor,
// selected tenant and client/caller remain separate. This is non-secret claim
// data, not evidence of authority until cryptographically validated.
type AccessTokenClaims struct {
	// Issuer binds the trusted issuer, not a requester-selected authority.
	Issuer string `json:"iss"`
	// Audience binds the exact intended verifier or consuming service.
	Audience string `json:"aud"`
	// Subject binds the exact authenticated subject, not an authorization decision.
	Subject string `json:"sub"`
	// ClientID identifies the authenticated calling workload, independently of the owner and actor.
	ClientID string `json:"client_id"`
	// IssuedAt is original token issuance in Unix seconds, never renewed by copying.
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is exclusive token expiry in Unix seconds, within five minutes and every finite ancestor.
	ExpiresAt int64 `json:"exp"`
	// TokenID identifies this exact token within the issuer and environment.
	TokenID string `json:"jti"`
	// Purpose binds one exact protected operation, never a wildcard.
	Purpose Purpose `json:"purpose"`
	// Environment separates otherwise identical issuer identities across deployment environments.
	Environment string `json:"environment"`
	// Method identifies the method that established authentication.
	Method string `json:"method"`
	// Assurance records the established closed authentication-strength classification.
	Assurance Assurance `json:"assurance"`
	// Owner identifies the credential's typed owner, not its creator or financial payer.
	Owner AuthorityOwner `json:"owner"`
	// Actor optionally binds a verified human actor; absence grants no human authority.
	Actor *AuthorityOwner `json:"actor,omitempty"`
	// Tenant binds the exact selected tenant; it is not inferred from the calling workload.
	Tenant string `json:"tenant"`
	// TenantVersion is the positive authoritative version of the selected tenant.
	TenantVersion uint64 `json:"tenant_version"`
	// ClientVersion is the positive authoritative version of the calling workload.
	ClientVersion uint64 `json:"client_version"`
	// SigningVersion binds the positive signing-key compromise/revocation dimension.
	SigningVersion uint64 `json:"signing_version"`
	// MembershipID binds the human actor's exact membership when Actor is present.
	MembershipID string `json:"membership_id,omitempty"`
	// MembershipVersion is the positive membership version required when Actor is present.
	MembershipVersion uint64 `json:"membership_version,omitempty"`
	// RootCredential retains the source credential ID, version and expiry ceiling.
	RootCredential AuthorityGrant `json:"root_credential"`
	// RootGrant retains the original grant ID, version and expiry ceiling.
	RootGrant AuthorityGrant `json:"root_grant"`
	// Parents contains the ordered, bounded delegation lineage without cycles.
	Parents []AuthorityGrant `json:"parents"`
	// Scopes contains unique canonical scopes asserted by the verified source.
	Scopes []string `json:"scopes"`
}

// ValidityDimensionKind is a closed authority invalidation dimension.
// Empty and unknown values are invalid; every applicable dimension is required.
type ValidityDimensionKind string

const (
	// ValidityRootCredential binds source credential revocation.
	ValidityRootCredential ValidityDimensionKind = "root-credential"
	// ValidityRootGrant binds original grant revocation.
	ValidityRootGrant ValidityDimensionKind = "root-grant"
	// ValidityParentGrant binds an intermediate delegated grant.
	ValidityParentGrant ValidityDimensionKind = "parent-grant"
	// ValidityOwner binds the credential owner's current status.
	ValidityOwner ValidityDimensionKind = "owner"
	// ValidityActor binds the optional verified human actor's status.
	ValidityActor ValidityDimensionKind = "actor"
	// ValidityTenant binds the selected tenant's current status.
	ValidityTenant ValidityDimensionKind = "tenant"
	// ValidityMembership binds the human actor's current membership.
	ValidityMembership ValidityDimensionKind = "membership"
	// ValidityClient binds the calling workload's current status.
	ValidityClient ValidityDimensionKind = "client"
	// ValiditySigning binds the selected signing key's compromise/revocation version.
	ValiditySigning ValidityDimensionKind = "signing"
)

// ValidityDimension is an exact non-secret ID/version binding, invalid at zero.
type ValidityDimension struct {
	// Kind selects the closed classification; unknown and zero values are invalid.
	Kind ValidityDimensionKind
	// ID identifies this exact proof or versioned authority node within its owning issuer.
	ID string
	// Version is the positive authoritative version of this exact identity or dimension.
	Version uint64
}

// DimensionValidity records one authoritative dimension. VerifiedAt is the
// original authoritative read START, not completion/cache-insertion time.
// ValidUntil is exclusive and at most 20 seconds later. Zero values are invalid.
// Every cache intermediary must preserve these original immutable timestamps.
type DimensionValidity struct {
	// Dimension binds one exact authority kind, identity and positive version.
	Dimension ValidityDimension
	// Active reports whether that exact authority dimension remains eligible.
	Active bool
	// VerifiedAt is the original authoritative read start, never cache insertion or response completion.
	VerifiedAt time.Time
	// ValidUntil is the original exclusive validity deadline, at most twenty seconds after VerifiedAt.
	ValidUntil time.Time
}

// ValidityRequest asks for the exact token dimensions, never caller overrides.
// The source may mutate its owned copy but cannot change validated token claims.
type ValidityRequest struct {
	// Claims contains the exact token dimensions whose current authority is required.
	Claims AccessTokenClaims
}

// SignedValidityEvidence is a source-issued typed, non-secret validity result.
// It is invalid at zero. Signature authenticates SigningBytes with the configured
// evidence trust key. Responses are bounded to 16 dimensions before copying.
type SignedValidityEvidence struct {
	// Issuer binds the trusted issuer, not a requester-selected authority.
	Issuer string
	// Environment separates otherwise identical issuer identities across deployment environments.
	Environment string
	// TokenID identifies this exact token within the issuer and environment.
	TokenID string
	// Tenant binds the exact selected tenant; it is not inferred from the calling workload.
	Tenant string
	// Dimensions contains every required exact validity dimension, bounded to sixteen entries.
	Dimensions []DimensionValidity
	// KeyID selects an explicitly configured trusted evidence key, not an arbitrary remote key.
	KeyID string
	// Signature is source-owned Ed25519 evidence and must not change during validation.
	Signature []byte
}

// SignedAuthenticationRecord is the original record of successful permanent
// account authentication, not an account-active/existence assertion. It is
// queried only by ProofID. Sources must never sign requester-created Proof data.
// Zero is invalid; exact Proof and permanent-subject equality are required.
type SignedAuthenticationRecord struct {
	// Issuer binds the trusted issuer, not a requester-selected authority.
	Issuer string
	// Environment separates otherwise identical issuer identities across deployment environments.
	Environment string
	// State must be SignInStateAuthenticated; anonymous, challenge and rejected outcomes cannot mint proofs.
	State SignInState
	// Permanent must assert actual successful permanent-account authentication, not account existence.
	Permanent bool
	// Proof retains the complete original structural proof binding; it is not sufficient authority by itself.
	Proof Proof
	// PermanentSubject is the non-anonymous permanent subject and must equal Proof.Subject.
	PermanentSubject string
	// CredentialID identifies the exact credential that completed verification.
	CredentialID string
	// CredentialVersion is the positive version of that authenticating credential.
	CredentialVersion uint64
	// KeyID selects an explicitly configured trusted evidence key, not an arbitrary remote key.
	KeyID string
	// Signature is source-owned Ed25519 evidence and must not change during validation.
	Signature []byte
}

// AuthoritySource supplies signed original authority evidence. Implementations
// must honor bounded context cancellation, bound decoding before allocation,
// and support concurrent calls. The application owns its lifecycle and signing
// custody. Optional warm caches preserve original timestamps; stale authority
// must not be served as newly verified. No source lookup runs under a lock.
type AuthoritySource interface {
	// CurrentValidity returns signed original dimension evidence without renewing source timestamps.
	CurrentValidity(context.Context, ValidityRequest) (SignedValidityEvidence, error)
	// PermanentAuthentication retrieves original successful permanent authentication by exact proof identity.
	PermanentAuthentication(context.Context, ProofID) (SignedAuthenticationRecord, error)
}

// AuthorityKey is a caller-owned Ed25519 public trust key. ID is 1..128 visible
// ASCII bytes and PublicKey is exactly 32 bytes. Constructor retains a copy.
type AuthorityKey struct {
	// ID is the unique canonical ASCII name of this configured trust key.
	ID string
	// PublicKey is a thirty-two-byte Ed25519 trust key copied at construction.
	PublicKey ed25519.PublicKey
}

// AuthorityConfig explicitly composes one trusted shared-issuer authority.
// Zero is invalid. Algorithm must be EdDSA and Profile shared-issuer-v1.
// Key sets contain 1..32 unique keys, scopes 0..128 unique ASCII values;
// MaximumDelegationDepth is 1..4. ReadTimeout and ClockUncertainty are positive,
// with a combined maximum of ten seconds. The application owns Source/Clock
// and must provide concurrency-safe implementations and a trusted bounded clock.
type AuthorityConfig struct {
	// Issuer binds the trusted issuer, not a requester-selected authority.
	Issuer string
	// Environment separates otherwise identical issuer identities across deployment environments.
	Environment string
	// Audience binds the exact intended verifier or consuming service.
	Audience string
	// Algorithm must be EdDSA for this explicitly selected profile.
	Algorithm string
	// Profile must be shared-issuer-v1; unknown profiles fail closed.
	Profile string
	// AccessKeys is the explicitly trusted access-token key set, copied at construction.
	AccessKeys []AuthorityKey
	// EvidenceKeys is the explicitly trusted signed-original evidence key set, copied at construction.
	EvidenceKeys []AuthorityKey
	// Source is caller-owned concurrent authority IO; it must honor bounded cancellation.
	Source AuthoritySource
	// Clock is a caller-owned, concurrency-safe trusted clock.
	Clock clock.Clock
	// ReadTimeout bounds each authority read and shares a ten-second budget with ClockUncertainty.
	ReadTimeout time.Duration
	// ClockUncertainty conservatively reduces validity and shares a ten-second budget with ReadTimeout.
	ClockUncertainty time.Duration
	// MaximumDelegationDepth limits parent exchanges to one through four; configuration may only lower the profile ceiling.
	MaximumDelegationDepth int
	// RequiredScopes contains the exact scopes every accepted token must carry, copied at construction.
	RequiredScopes []string
}

// ResourcePrincipal is an immutable verified resource identity with the
// original absolute validity deadline. Zero is invalid. It is safe to copy
// concurrently and owns no resource; copying never renews authority freshness.
type ResourcePrincipal struct {
	claims     AccessTokenClaims
	validUntil time.Time
	valid      bool
}

// Bindings returns defensive copies of non-secret validated token bindings.
// The returned projection alone is not an authorization decision.
func (p ResourcePrincipal) Bindings() AccessTokenClaims { return copyAccessClaims(p.claims) }

// ValidUntil returns the earliest original authority deadline, conservatively
// reduced by the configured clock-uncertainty budget; zero indicates invalid.
func (p ResourcePrincipal) ValidUntil() time.Time { return p.validUntil }

// Validate rejects invalid, future-issued or expired cached principal copies.
// Now comes from the trusted caller clock. It owns no resources.
func (p ResourcePrincipal) Validate(now time.Time) error {
	if !p.valid || now.IsZero() || now.Before(time.Unix(p.claims.IssuedAt, 0)) {
		return ErrInvalidProof
	}
	if !now.Before(p.validUntil) {
		return ErrExpiredProof
	}
	return nil
}

// PermanentAccountProof is an immutable authority-issued proof. Zero is invalid.
// Only the issuing trusted composition's ValidatePermanentAccountProof may
// establish authority; Bindings exposes a non-secret projection, never the
// private minting capability. Copies are concurrency safe and own no resources.
type PermanentAccountProof struct {
	bindings   PermanentAccountProofSpec
	capability *mintingCapability
}

// PermanentAccountProofSpec is caller-owned issuer input. The proof is complete
// and permanent subject is required, non-anonymous and exactly Proof.Subject.
// Input values alone never confer authority to mint a proof.
type PermanentAccountProofSpec struct {
	// Proof retains the complete original structural proof binding; it is not sufficient authority by itself.
	Proof Proof
	// PermanentSubject is the non-anonymous permanent subject and must equal Proof.Subject.
	PermanentSubject string
}

// Bindings returns bounded non-secret bindings, not replaceable authority
// evidence. Validate through the expected configured authority instance.
func (p PermanentAccountProof) Bindings() PermanentAccountProofSpec { return p.bindings }

// PermanentAccountProofIssuer is the explicitly injected authority-issued result
// boundary. Implementing this interface grants no private minting capability.
type PermanentAccountProofIssuer interface {
	// IssuePermanentAccountProof validates original permanent authentication before minting instance-bound proof.
	IssuePermanentAccountProof(context.Context, PermanentAccountProofSpec) (PermanentAccountProof, error)
}

// SigningBytes returns the bounded, domain-separated v1 canonical signed
// validity projection, excluding Signature. It contains no secret. Signing
// these bytes does not confer package minting authority. Invalid zero/structure
// returns ErrInvalidProof without interpolating input. Callers own the result.
func (e SignedValidityEvidence) SigningBytes() ([]byte, error) {
	if !identifier(e.Issuer) || !identifier(e.Environment) || !canonicalASCII(e.TokenID, 22, 128) || !identifier(e.Tenant) || !canonicalASCII(e.KeyID, 1, 128) || len(e.Dimensions) == 0 || len(e.Dimensions) > 16 {
		return nil, ErrInvalidProof
	}
	seen := make(map[ValidityDimension]bool, len(e.Dimensions))
	copy := e
	copy.Signature = nil
	copy.Dimensions = append([]DimensionValidity(nil), e.Dimensions...)
	for i, d := range copy.Dimensions {
		if !validDimension(d.Dimension) || seen[d.Dimension] || d.VerifiedAt.IsZero() || !d.VerifiedAt.Before(d.ValidUntil) || d.ValidUntil.Sub(d.VerifiedAt) > 20*time.Second {
			return nil, ErrInvalidProof
		}
		seen[d.Dimension] = true
		copy.Dimensions[i].VerifiedAt = d.VerifiedAt.UTC()
		copy.Dimensions[i].ValidUntil = d.ValidUntil.UTC()
	}
	bytes, err := json.Marshal(copy)
	if err != nil {
		return nil, ErrInvalidProof
	}
	return append([]byte("golib/shared-issuer-v1/validity\x00"), bytes...), nil
}

// SigningBytes returns the domain-separated v1 original-authentication record,
// excluding Signature. Only an authority that actually performed successful
// permanent authentication may issue this record. Merely signing account
// existence/requester data violates the source contract. No secret is returned.
func (r SignedAuthenticationRecord) SigningBytes() ([]byte, error) {
	if !identifier(r.Issuer) || !identifier(r.Environment) || r.State != SignInStateAuthenticated || !r.Permanent || !r.Proof.valid() || r.Proof.Purpose != "permanent-account-upgrade" || !identifier(r.PermanentSubject) || r.PermanentSubject != r.Proof.Subject || !identifier(r.CredentialID) || r.CredentialVersion == 0 || !canonicalASCII(r.KeyID, 1, 128) {
		return nil, ErrInvalidProof
	}
	copy := r
	copy.Signature = nil
	copy.Proof.IssuedAt = r.Proof.IssuedAt.UTC()
	copy.Proof.ExpiresAt = r.Proof.ExpiresAt.UTC()
	bytes, err := json.Marshal(copy)
	if err != nil {
		return nil, ErrInvalidProof
	}
	return append([]byte("golib/shared-issuer-v1/permanent-authentication\x00"), bytes...), nil
}

func validDimension(d ValidityDimension) bool {
	if !identifier(d.ID) || d.Version == 0 {
		return false
	}
	switch d.Kind {
	case ValidityRootCredential, ValidityRootGrant, ValidityParentGrant, ValidityOwner, ValidityActor, ValidityTenant, ValidityMembership, ValidityClient, ValiditySigning:
		return true
	default:
		return false
	}
}

func copyAccessClaims(c AccessTokenClaims) AccessTokenClaims {
	if c.Actor != nil {
		actor := *c.Actor
		c.Actor = &actor
	}
	c.Parents = append([]AuthorityGrant(nil), c.Parents...)
	c.Scopes = append([]string(nil), c.Scopes...)
	return c
}

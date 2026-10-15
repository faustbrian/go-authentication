package authentication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-clock"
)

type mintingCapability struct{ identity byte }

// AuthorityAuthenticator owns immutable trusted composition for the bounded
// shared-issuer-v1 EdDSA profile. Zero is invalid; use NewAuthorityAuthenticator.
// It owns no goroutine, cache, key rotation service or source lifecycle. Sources
// own optional warm caches, but cannot renew signed original timestamps. Methods
// support concurrent calls when the injected source and clock do likewise.
type AuthorityAuthenticator struct {
	issuer           string
	environment      string
	audience         string
	accessKeys       map[string]ed25519.PublicKey
	evidenceKeys     map[string]ed25519.PublicKey
	source           AuthoritySource
	clock            clock.Clock
	readTimeout      time.Duration
	clockUncertainty time.Duration
	maximumDepth     int
	requiredScopes   []string
	capability       *mintingCapability
}

// NewAuthorityAuthenticator validates the explicit selected profile, copies
// keys/scopes and privately creates the composition's minting capability.
// No authentication or source read occurs. Distinct compositions have distinct
// authority identities even if configured with identical public values.
func NewAuthorityAuthenticator(config AuthorityConfig) (*AuthorityAuthenticator, error) {
	if !identifier(config.Issuer) || !identifier(config.Environment) || !identifier(config.Audience) || config.Algorithm != "EdDSA" || config.Profile != "shared-issuer-v1" ||
		isNil(config.Source) || isNil(config.Clock) || config.ReadTimeout <= 0 || config.ClockUncertainty <= 0 || config.ClockUncertainty > 10*time.Second-config.ReadTimeout || config.MaximumDelegationDepth < 1 || config.MaximumDelegationDepth > 4 || !validScopes(config.RequiredScopes) {
		return nil, ErrInvalidConfiguration
	}
	access, err := copyAuthorityKeys(config.AccessKeys)
	if err != nil {
		return nil, err
	}
	evidence, err := copyAuthorityKeys(config.EvidenceKeys)
	if err != nil {
		return nil, err
	}
	return &AuthorityAuthenticator{issuer: strings.Clone(config.Issuer), environment: strings.Clone(config.Environment), audience: strings.Clone(config.Audience), accessKeys: access, evidenceKeys: evidence, source: config.Source, clock: config.Clock, readTimeout: config.ReadTimeout, clockUncertainty: config.ClockUncertainty, maximumDepth: config.MaximumDelegationDepth, requiredScopes: cloneStrings(config.RequiredScopes), capability: &mintingCapability{identity: 1}}, nil
}

func copyAuthorityKeys(keys []AuthorityKey) (map[string]ed25519.PublicKey, error) {
	if len(keys) == 0 || len(keys) > 32 {
		return nil, ErrInvalidConfiguration
	}
	result := make(map[string]ed25519.PublicKey, len(keys))
	for _, key := range keys {
		if !canonicalASCII(key.ID, 1, 128) || len(key.PublicKey) != ed25519.PublicKeySize || result[key.ID] != nil {
			return nil, ErrInvalidConfiguration
		}
		result[strings.Clone(key.ID)] = append(ed25519.PublicKey(nil), key.PublicKey...)
	}
	return result, nil
}

// Authenticate validates an access bearer token and current authority before
// producing the unchanged Principal/Result contract. It never accepts ID tokens
// or infers tenant authority from client authentication. Resource consumers that
// need typed owner/actor/caller/lineage use ValidateAccessToken directly.
// The legacy Principal is a current-request projection, not reusable revocation
// evidence: retained results require ResourcePrincipal.Validate at each use.
func (a *AuthorityAuthenticator) Authenticate(ctx context.Context, credential Credential) (Result, error) {
	var token string
	switch c := credential.(type) {
	case BearerCredential:
		token = c.Token()
	case *BearerCredential:
		if c != nil {
			token = c.Token()
		}
	default:
		return Result{}, NewFailure(FailureInvalid)
	}
	resource, err := a.ValidateAccessToken(ctx, token)
	if err != nil {
		return Result{}, err
	}
	c := resource.claims
	// Use the current principal admission/copy boundary rather than bypass it
	// when projecting verified authority into the ordinary authentication API.
	principal, err := NewPrincipal(PrincipalSpec{
		Subject: c.Subject, Method: c.Method, Issuer: c.Issuer,
		Audiences: []string{c.Audience}, Scopes: c.Scopes,
		AuthenticatedAt: time.Unix(c.IssuedAt, 0),
	})
	if err != nil {
		return Result{}, NewFailure(FailureRejected)
	}
	return NewAuthenticatedResult(principal)
}

// ValidateAccessToken verifies a bounded compact EdDSA access token locally,
// then verifies signed current validity for every exact applicable dimension.
// At most 16 KiB is accepted before decoding/cryptographic work. Source reads
// derive a bounded context; late, stale, unavailable or mismatched evidence
// fails closed. No background refresh or per-request central lookup is required:
// a source may serve still-valid signed original evidence from its warm cache.
func (a *AuthorityAuthenticator) ValidateAccessToken(ctx context.Context, token string) (ResourcePrincipal, error) {
	if a == nil || a.capability == nil {
		return ResourcePrincipal{}, ErrInvalidConfiguration
	}
	if ctx == nil {
		return ResourcePrincipal{}, NewFailure(FailureUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return ResourcePrincipal{}, NewFailure(FailureUnavailable)
	}
	if len(token) == 0 || len(token) > 16*1024 {
		return ResourcePrincipal{}, NewFailure(FailureInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ResourcePrincipal{}, NewFailure(FailureInvalid)
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return ResourcePrincipal{}, NewFailure(FailureInvalid)
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if !decodeClosedJSON(headerBytes, &header) || header.Algorithm != "EdDSA" || header.Type != "at+jwt" || !canonicalASCII(header.KeyID, 1, 128) {
		return ResourcePrincipal{}, NewFailure(FailureInvalid)
	}
	key := a.accessKeys[header.KeyID]
	if key == nil {
		return ResourcePrincipal{}, NewFailure(FailureRejected)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return ResourcePrincipal{}, NewFailure(FailureRejected)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return ResourcePrincipal{}, NewFailure(FailureRejected)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return ResourcePrincipal{}, NewFailure(FailureInvalid)
	}
	var claims AccessTokenClaims
	if !decodeClosedJSON(payload, &claims) {
		return ResourcePrincipal{}, NewFailure(FailureInvalid)
	}
	started := a.clock.Now()
	if !a.validClaims(claims, started) {
		return ResourcePrincipal{}, NewFailure(FailureRejected)
	}
	bounded, cancel := context.WithTimeout(ctx, a.readTimeout)
	defer cancel()
	evidence, err := a.source.CurrentValidity(bounded, ValidityRequest{Claims: copyAccessClaims(claims)})
	now := a.clock.Now()
	if err != nil || bounded.Err() != nil || now.Before(started) || now.Sub(started) > a.readTimeout {
		return ResourcePrincipal{}, NewFailure(FailureUnavailable)
	}
	deadline, err := a.verifyValidity(claims, header.KeyID, evidence, now)
	if err != nil {
		return ResourcePrincipal{}, err
	}
	return ResourcePrincipal{claims: copyAccessClaims(claims), validUntil: deadline, valid: true}, nil
}

func (a *AuthorityAuthenticator) validClaims(c AccessTokenClaims, now time.Time) bool {
	if c.Issuer != a.issuer || c.Environment != a.environment || c.Audience != a.audience || c.Purpose != "access-token" || !identifier(c.Subject) || !identifier(c.ClientID) || !identifier(c.Tenant) || !canonicalASCII(c.TokenID, 22, 128) || !identifier(c.Method) || !c.Assurance.valid() || c.TenantVersion == 0 || c.ClientVersion == 0 || c.SigningVersion == 0 || c.IssuedAt <= 0 || c.ExpiresAt-c.IssuedAt > 300 || now.IsZero() || now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt || !validOwner(c.Owner) || c.Subject != c.Owner.ID || c.Owner.Kind == AuthorityOwnerWorkload || len(c.Parents) > a.maximumDepth || !validScopes(c.Scopes) {
		return false
	}
	if c.Actor != nil {
		if !validOwner(*c.Actor) || c.Actor.Kind != AuthorityOwnerUser || !identifier(c.MembershipID) || c.MembershipVersion == 0 {
			return false
		}
	} else if c.MembershipID != "" || c.MembershipVersion != 0 {
		return false
	}
	expires := time.Unix(c.ExpiresAt, 0)
	if !validGrant(c.RootCredential, expires) || !validGrant(c.RootGrant, expires) || c.RootGrant.ID == c.TokenID {
		return false
	}
	seen := map[string]bool{c.RootGrant.ID: true, c.TokenID: true}
	ceiling := c.RootGrant.ExpiresAt
	for _, parent := range c.Parents {
		if !validGrant(parent, expires) || parent.ExpiresAt.IsZero() || seen[parent.ID] || (!ceiling.IsZero() && parent.ExpiresAt.After(ceiling)) {
			return false
		}
		seen[parent.ID] = true
		ceiling = parent.ExpiresAt
	}
	for _, required := range a.requiredScopes {
		if !containsString(c.Scopes, required) {
			return false
		}
	}
	return true
}

func validOwner(owner AuthorityOwner) bool {
	return identifier(owner.ID) && owner.Version > 0 && (owner.Kind == AuthorityOwnerUser || owner.Kind == AuthorityOwnerOrganization || owner.Kind == AuthorityOwnerWorkload)
}
func validGrant(grant AuthorityGrant, childExpiry time.Time) bool {
	return identifier(grant.ID) && grant.Version > 0 && (grant.ExpiresAt.IsZero() || !childExpiry.After(grant.ExpiresAt))
}
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func validScopes(scopes []string) bool {
	if len(scopes) > 128 {
		return false
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if !canonicalASCII(scope, 1, 128) || seen[scope] {
			return false
		}
		seen[scope] = true
	}
	return true
}

func expectedDimensions(c AccessTokenClaims, keyID string) []ValidityDimension {
	d := []ValidityDimension{
		{Kind: ValidityRootCredential, ID: c.RootCredential.ID, Version: c.RootCredential.Version},
		{Kind: ValidityRootGrant, ID: c.RootGrant.ID, Version: c.RootGrant.Version},
		{Kind: ValidityOwner, ID: c.Owner.ID, Version: c.Owner.Version},
		{Kind: ValidityTenant, ID: c.Tenant, Version: c.TenantVersion},
		{Kind: ValidityClient, ID: c.ClientID, Version: c.ClientVersion},
		{Kind: ValiditySigning, ID: keyID, Version: c.SigningVersion},
	}
	for _, p := range c.Parents {
		d = append(d, ValidityDimension{Kind: ValidityParentGrant, ID: p.ID, Version: p.Version})
	}
	if c.Actor != nil {
		d = append(d, ValidityDimension{Kind: ValidityActor, ID: c.Actor.ID, Version: c.Actor.Version}, ValidityDimension{Kind: ValidityMembership, ID: c.MembershipID, Version: c.MembershipVersion})
	}
	return d
}

func (a *AuthorityAuthenticator) verifyValidity(c AccessTokenClaims, keyID string, e SignedValidityEvidence, now time.Time) (time.Time, error) {
	bytes, err := e.SigningBytes()
	if err != nil || e.Issuer != c.Issuer || e.Environment != c.Environment || e.TokenID != c.TokenID || e.Tenant != c.Tenant || len(e.Signature) != ed25519.SignatureSize {
		return time.Time{}, NewFailure(FailureRejected)
	}
	key := a.evidenceKeys[e.KeyID]
	if key == nil || !ed25519.Verify(key, bytes, e.Signature) {
		return time.Time{}, NewFailure(FailureRejected)
	}
	expected := expectedDimensions(c, keyID)
	if len(e.Dimensions) != len(expected) {
		return time.Time{}, NewFailure(FailureRejected)
	}
	deadline := time.Unix(c.ExpiresAt, 0)
	for _, dimension := range expected {
		found := false
		for _, entry := range e.Dimensions {
			if entry.Dimension != dimension {
				continue
			}
			if !entry.Active || entry.VerifiedAt.After(now.Add(a.clockUncertainty)) {
				return time.Time{}, NewFailure(FailureRejected)
			}
			conservative := entry.ValidUntil.Add(-a.clockUncertainty)
			if !now.Before(conservative) {
				return time.Time{}, NewFailure(FailureRejected)
			}
			if conservative.Before(deadline) {
				deadline = conservative
			}
			found = true
		}
		if !found {
			return time.Time{}, NewFailure(FailureRejected)
		}
	}
	if !now.Before(deadline) {
		return time.Time{}, NewFailure(FailureRejected)
	}
	return deadline, nil
}

// PermanentAccountProofIssuerFromAuthenticator accepts only a package-owned
// trusted composition carrying its private capability. Arbitrary external
// authenticators/issuers, public Composite bindings and zero configurations are
// rejected. It performs no authentication and retains no caller credential.
func PermanentAccountProofIssuerFromAuthenticator(authenticator Authenticator) (PermanentAccountProofIssuer, error) {
	a, ok := authenticator.(*AuthorityAuthenticator)
	if !ok || a == nil || a.capability == nil {
		return nil, ErrInvalidConfiguration
	}
	return &permanentAccountIssuer{authority: a}, nil
}

type permanentAccountIssuer struct{ authority *AuthorityAuthenticator }

func (i *permanentAccountIssuer) IssuePermanentAccountProof(ctx context.Context, spec PermanentAccountProofSpec) (PermanentAccountProof, error) {
	a := i.authority
	if ctx == nil || ctx.Err() != nil {
		return PermanentAccountProof{}, NewFailure(FailureUnavailable)
	}
	use := ProofUse{Tenant: spec.Proof.Tenant, Subject: spec.PermanentSubject, Purpose: "permanent-account-upgrade", Audience: a.audience, Now: a.clock.Now()}
	if !identifier(spec.PermanentSubject) {
		return PermanentAccountProof{}, ErrInvalidProof
	}
	if err := spec.Proof.Validate(use); err != nil {
		return PermanentAccountProof{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, a.readTimeout)
	defer cancel()
	started := a.clock.Now()
	record, err := a.source.PermanentAuthentication(bounded, spec.Proof.ID)
	now := a.clock.Now()
	if err != nil || bounded.Err() != nil || now.Before(started) || now.Sub(started) > a.readTimeout {
		return PermanentAccountProof{}, NewFailure(FailureUnavailable)
	}
	bytes, err := record.SigningBytes()
	key := a.evidenceKeys[record.KeyID]
	if err != nil || key == nil || len(record.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, bytes, record.Signature) || record.Issuer != a.issuer || record.Environment != a.environment || record.PermanentSubject != spec.PermanentSubject || !equalProof(record.Proof, spec.Proof) {
		return PermanentAccountProof{}, ErrInvalidProof
	}
	use.Now = now
	if err := record.Proof.Validate(use); err != nil {
		return PermanentAccountProof{}, err
	}
	// SigningBytes and Validate have independently established construction
	// validity; NewProof now provides the required defensive string copies.
	proof, _ := NewProof(ProofSpec(record.Proof))
	return PermanentAccountProof{bindings: PermanentAccountProofSpec{Proof: proof, PermanentSubject: strings.Clone(record.PermanentSubject)}, capability: a.capability}, nil
}

// ValidatePermanentAccountProof verifies private capability identity against
// THIS trusted composition, then rechecks complete exact proof use. Proofs from
// any other composition, including one configured with self-signed public keys,
// cannot authenticate authority here. Bindings alone must never be substituted.
func (a *AuthorityAuthenticator) ValidatePermanentAccountProof(proof PermanentAccountProof, use ProofUse) error {
	if a == nil || a.capability == nil || proof.capability != a.capability || proof.bindings.PermanentSubject != use.Subject {
		return ErrInvalidProof
	}
	if use.Purpose != "permanent-account-upgrade" {
		return ErrProofPurposeMismatch
	}
	return proof.bindings.Proof.Validate(use)
}

func equalProof(a, b Proof) bool {
	return a.ID == b.ID && a.Tenant == b.Tenant && a.Subject == b.Subject && a.Method == b.Method && a.Assurance == b.Assurance && a.Purpose == b.Purpose && a.Audience == b.Audience && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

func decodeClosedJSON(data []byte, target any) bool {
	if len(data) == 0 || len(data) > 16*1024 || !utf8.Valid(data) {
		return false
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	if !scanJSONValue(scanner, 0) {
		return false
	}
	if _, err := scanner.Token(); err != io.EOF {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil
}

func scanJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			// Every profile field uses lowercase ASCII. Go's tagged struct
			// decoder also matches case-folded aliases (including Unicode),
			// which must not become a second spelling or bypass duplicates.
			if !ok || !canonicalASCII(name, 1, 256) || name != strings.ToLower(name) || len(seen) >= 128 || seen[name] {
				return false
			}
			seen[name] = true
			if !scanJSONValue(decoder, depth+1) {
				return false
			}
		}
	case '[':
		count := 0
		for decoder.More() {
			if count >= 256 || !scanJSONValue(decoder, depth+1) {
				return false
			}
			count++
		}
	}
	_, err = decoder.Token()
	return err == nil
}

var _ Authenticator = (*AuthorityAuthenticator)(nil)

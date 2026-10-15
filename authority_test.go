package authentication_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

type authorityClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *authorityClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *authorityClock) advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

type authoritySource struct {
	validity auth.SignedValidityEvidence
	record   auth.SignedAuthenticationRecord
	err      error
}

func (s *authoritySource) CurrentValidity(context.Context, auth.ValidityRequest) (auth.SignedValidityEvidence, error) {
	return s.validity, s.err
}
func (s *authoritySource) PermanentAuthentication(context.Context, auth.ProofID) (auth.SignedAuthenticationRecord, error) {
	return s.record, s.err
}

func authorityFixture(t *testing.T) (*auth.AuthorityAuthenticator, *authoritySource, *authorityClock, ed25519.PrivateKey, auth.AccessTokenClaims) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := &authorityClock{now: proofSpec().IssuedAt.Add(time.Second)}
	claims := auth.AccessTokenClaims{
		Issuer: "https://issuer.example", Environment: "test", Audience: "resource", Subject: "subject", ClientID: "workload", TokenID: "abcdefghijklmnopqrstuv",
		Purpose: "access-token", Method: "password", Assurance: auth.AssuranceMultiFactor, IssuedAt: clock.Now().Unix() - 1, ExpiresAt: clock.Now().Unix() + 60,
		Owner: auth.AuthorityOwner{Kind: auth.AuthorityOwnerUser, ID: "subject", Version: 1}, Tenant: "tenant", TenantVersion: 1, ClientVersion: 1, SigningVersion: 1,
		RootCredential: auth.AuthorityGrant{ID: "credential", Version: 1}, RootGrant: auth.AuthorityGrant{ID: "grant", Version: 1, ExpiresAt: clock.Now().Add(time.Hour)}, Scopes: []string{"read"},
	}
	evidence := auth.SignedValidityEvidence{Issuer: claims.Issuer, Environment: claims.Environment, TokenID: claims.TokenID, Tenant: claims.Tenant, KeyID: "key"}
	for _, dimension := range []auth.ValidityDimension{
		{Kind: auth.ValidityRootCredential, ID: "credential", Version: 1}, {Kind: auth.ValidityRootGrant, ID: "grant", Version: 1},
		{Kind: auth.ValidityOwner, ID: "subject", Version: 1}, {Kind: auth.ValidityTenant, ID: "tenant", Version: 1},
		{Kind: auth.ValidityClient, ID: "workload", Version: 1}, {Kind: auth.ValiditySigning, ID: "key", Version: 1},
	} {
		evidence.Dimensions = append(evidence.Dimensions, auth.DimensionValidity{Dimension: dimension, Active: true, VerifiedAt: clock.Now(), ValidUntil: clock.Now().Add(20 * time.Second)})
	}
	bytes, err := evidence.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	evidence.Signature = ed25519.Sign(key, bytes)
	source := &authoritySource{validity: evidence}
	authority, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: claims.Issuer, Environment: "test", Audience: "resource", Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: []auth.AuthorityKey{{ID: "key", PublicKey: pub}}, EvidenceKeys: []auth.AuthorityKey{{ID: "key", PublicKey: pub}}, Source: source, Clock: clock, ReadTimeout: time.Second, ClockUncertainty: time.Second, MaximumDelegationDepth: 4, RequiredScopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	return authority, source, clock, key, claims
}

func signedAccess(t *testing.T, key ed25519.PrivateKey, claims auth.AccessTokenClaims) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"at+jwt","kid":"key"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(encoded)))
}

func TestTrustedAuthorityValidatesAccessAndFreshnessWithoutRenewal(t *testing.T) {
	authority, source, clock, key, claims := authorityFixture(t)
	principal, err := authority.ValidateAccessToken(context.Background(), signedAccess(t, key, claims))
	if err != nil {
		t.Fatal(err)
	}
	if principal.Bindings().Owner.ID != "subject" || principal.Bindings().ClientID != "workload" {
		t.Fatal("owner and caller collapsed")
	}
	clock.advance(19 * time.Second)
	if err := principal.Validate(clock.Now()); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("original evidence expiry was renewed")
	}
	if _, err := authority.ValidateAccessToken(context.Background(), signedAccess(t, key, claims)); err == nil {
		t.Fatal("warm stale evidence accepted")
	}
	source.err = errors.New("provider unavailable")
	if _, err := authority.ValidateAccessToken(context.Background(), signedAccess(t, key, claims)); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("outage did not fail closed")
	}
}

func TestTrustedPermanentIssuanceRequiresOriginalExactAuthentication(t *testing.T) {
	authority, source, clock, key, _ := authorityFixture(t)
	spec := proofSpec()
	spec.Purpose = "permanent-account-upgrade"
	spec.Audience = "resource"
	spec.IssuedAt = clock.Now()
	spec.ExpiresAt = clock.Now().Add(time.Minute)
	proof, _ := auth.NewProof(spec)
	source.record = auth.SignedAuthenticationRecord{Issuer: "https://issuer.example", Environment: "test", State: auth.SignInStateAuthenticated, Permanent: true, Proof: proof, PermanentSubject: "subject", CredentialID: "credential", CredentialVersion: 1, KeyID: "key"}
	bytes, err := source.record.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	source.record.Signature = ed25519.Sign(key, bytes)
	issuer, err := auth.PermanentAccountProofIssuerFromAuthenticator(authority)
	if err != nil {
		t.Fatal(err)
	}
	permanent, err := issuer.IssuePermanentAccountProof(context.Background(), auth.PermanentAccountProofSpec{Proof: proof, PermanentSubject: "subject"})
	if err != nil {
		t.Fatal(err)
	}
	use := auth.ProofUse{Tenant: "tenant", Subject: "subject", Purpose: "permanent-account-upgrade", Audience: "resource", Now: clock.Now()}
	if err := authority.ValidatePermanentAccountProof(permanent, use); err != nil {
		t.Fatal(err)
	}
	other, _, _, _, _ := authorityFixture(t)
	if err := other.ValidatePermanentAccountProof(permanent, use); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("another authority accepted capability")
	}
	proof.ID = "abcdefghijklmnopqrstuw"
	if _, err := issuer.IssuePermanentAccountProof(context.Background(), auth.PermanentAccountProofSpec{Proof: proof, PermanentSubject: "subject"}); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("caller-created proof received authority")
	}
}

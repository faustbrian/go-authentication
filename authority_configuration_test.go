package authentication_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func fixtureConfig(t *testing.T) (auth.AuthorityConfig, *authoritySource, *authorityClock, ed25519.PrivateKey, auth.AccessTokenClaims) {
	t.Helper()
	_, source, clock, key, c := authorityFixture(t)
	pub := key.Public().(ed25519.PublicKey)
	return auth.AuthorityConfig{Issuer: c.Issuer, Environment: c.Environment, Audience: c.Audience, Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: []auth.AuthorityKey{{ID: "key", PublicKey: pub}}, EvidenceKeys: []auth.AuthorityKey{{ID: "key", PublicKey: pub}}, Source: source, Clock: clock, ReadTimeout: time.Second, ClockUncertainty: time.Second, MaximumDelegationDepth: 4, RequiredScopes: []string{"read"}}, source, clock, key, c
}

func TestAuthorityConfigurationRejectsUnsafeAndUnboundedComposition(t *testing.T) {
	for _, mutate := range []func(*auth.AuthorityConfig){
		func(c *auth.AuthorityConfig) { c.Issuer = "" }, func(c *auth.AuthorityConfig) { c.Environment = "" }, func(c *auth.AuthorityConfig) { c.Audience = "" },
		func(c *auth.AuthorityConfig) { c.Algorithm = "none" }, func(c *auth.AuthorityConfig) { c.Profile = "other" }, func(c *auth.AuthorityConfig) { c.Source = nil }, func(c *auth.AuthorityConfig) { c.Clock = nil },
		func(c *auth.AuthorityConfig) { c.ReadTimeout = 0 }, func(c *auth.AuthorityConfig) { c.ReadTimeout = 11 * time.Second }, func(c *auth.AuthorityConfig) { c.ClockUncertainty = 0 }, func(c *auth.AuthorityConfig) { c.ClockUncertainty = 10 * time.Second },
		func(c *auth.AuthorityConfig) { c.MaximumDelegationDepth = 0 }, func(c *auth.AuthorityConfig) { c.MaximumDelegationDepth = 5 }, func(c *auth.AuthorityConfig) { c.RequiredScopes = []string{"read", "read"} },
		func(c *auth.AuthorityConfig) { c.AccessKeys = nil }, func(c *auth.AuthorityConfig) { c.AccessKeys = make([]auth.AuthorityKey, 33) }, func(c *auth.AuthorityConfig) { c.AccessKeys = append(c.AccessKeys, c.AccessKeys[0]) },
		func(c *auth.AuthorityConfig) { c.AccessKeys[0].ID = "" }, func(c *auth.AuthorityConfig) { c.AccessKeys[0].ID = strings.Repeat("a", 129) }, func(c *auth.AuthorityConfig) { c.AccessKeys[0].PublicKey = nil },
		func(c *auth.AuthorityConfig) { c.EvidenceKeys = nil }, func(c *auth.AuthorityConfig) { c.EvidenceKeys[0].PublicKey = make([]byte, 33) },
	} {
		config, _, _, _, _ := fixtureConfig(t)
		mutate(&config)
		if _, err := auth.NewAuthorityAuthenticator(config); !errors.Is(err, auth.ErrInvalidConfiguration) {
			t.Fatal("unsafe authority configuration accepted")
		}
	}
	config, _, _, key, claims := fixtureConfig(t)
	a, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	config.AccessKeys[0].PublicKey[0] ^= 1
	config.EvidenceKeys[0].ID = "changed"
	config.RequiredScopes[0] = "changed"
	if _, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, claims)); err != nil {
		t.Fatal("caller mutation changed trusted composition", err)
	}
}

func TestAuthorityConfigurationAcceptsExactInclusivePolicyLimits(t *testing.T) {
	for _, mutate := range []func(*auth.AuthorityConfig){
		func(c *auth.AuthorityConfig) { c.MaximumDelegationDepth = 1 },
		func(c *auth.AuthorityConfig) { c.ReadTimeout = 9 * time.Second; c.ClockUncertainty = time.Second },
		func(c *auth.AuthorityConfig) {
			key := c.AccessKeys[0].PublicKey
			for i := 1; i < 32; i++ {
				c.AccessKeys = append(c.AccessKeys, auth.AuthorityKey{ID: fmt.Sprintf("key-%d", i), PublicKey: key})
			}
			c.EvidenceKeys = append([]auth.AuthorityKey(nil), c.AccessKeys...)
		},
	} {
		config, _, _, _, _ := fixtureConfig(t)
		mutate(&config)
		if _, err := auth.NewAuthorityAuthenticator(config); err != nil {
			t.Fatal("inclusive authority boundary rejected", err)
		}
	}
}

type externalAuthority struct{ called bool }

func (a *externalAuthority) Authenticate(context.Context, auth.Credential) (auth.Result, error) {
	a.called = true
	return auth.Result{}, nil
}
func (a *externalAuthority) IssuePermanentAccountProof(context.Context, auth.PermanentAccountProofSpec) (auth.PermanentAccountProof, error) {
	a.called = true
	return auth.PermanentAccountProof{}, nil
}

func TestPermanentIssuerFactoryRejectsPublicImplementationsWithoutAuthentication(t *testing.T) {
	external := &externalAuthority{}
	composite, err := auth.NewComposite([]auth.Binding{{Kind: auth.CredentialBearer, Authenticator: external}})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []auth.Authenticator{nil, external, composite, (*auth.AuthorityAuthenticator)(nil), new(auth.AuthorityAuthenticator)} {
		if _, err := auth.PermanentAccountProofIssuerFromAuthenticator(candidate); !errors.Is(err, auth.ErrInvalidConfiguration) {
			t.Fatal("external implementation gained minting capability")
		}
	}
	if external.called {
		t.Fatal("factory authenticated as a side effect")
	}
}

type delayedAuthoritySource struct {
	source *authoritySource
	clock  *authorityClock
	delay  time.Duration
}

func (s delayedAuthoritySource) CurrentValidity(ctx context.Context, r auth.ValidityRequest) (auth.SignedValidityEvidence, error) {
	s.clock.advance(s.delay)
	return s.source.CurrentValidity(ctx, r)
}
func (s delayedAuthoritySource) PermanentAuthentication(ctx context.Context, id auth.ProofID) (auth.SignedAuthenticationRecord, error) {
	s.clock.advance(s.delay)
	return s.source.PermanentAuthentication(ctx, id)
}

func TestAuthorityReadDelayAndClockRollbackCannotExtendFreshness(t *testing.T) {
	for _, delay := range []time.Duration{2 * time.Second, -time.Second} {
		config, source, clock, key, claims := fixtureConfig(t)
		config.Source = delayedAuthoritySource{source: source, clock: clock, delay: delay}
		a, err := auth.NewAuthorityAuthenticator(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, claims)); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
			t.Fatal("unbounded or backward read accepted")
		}
	}
}

func TestAuthoritativeReadAcceptsExactTimeoutWithoutRenewingEvidence(t *testing.T) {
	config, source, clock, key, claims := fixtureConfig(t)
	started := clock.Now()
	config.Source = delayedAuthoritySource{source: source, clock: clock, delay: config.ReadTimeout}
	a, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, claims))
	if err != nil {
		t.Fatal("read at exact budget rejected", err)
	}
	if !principal.ValidUntil().Equal(started.Add(19 * time.Second)) {
		t.Fatal("read completion renewed original deadline")
	}

	_, source, clock, key, spec := permanentFixture(t)
	config, _, _, _, _ = fixtureConfig(t)
	config.Source, config.Clock = delayedAuthoritySource{source: source, clock: clock, delay: config.ReadTimeout}, clock
	config.AccessKeys[0].PublicKey, config.EvidenceKeys[0].PublicKey = key.Public().(ed25519.PublicKey), key.Public().(ed25519.PublicKey)
	a, err = auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permanentIssuer(t, a).IssuePermanentAccountProof(context.Background(), spec); err != nil {
		t.Fatal("permanent read at exact budget rejected", err)
	}
}

func TestSignedEvidenceStructuralBounds(t *testing.T) {
	for _, mutate := range []func(*auth.SignedValidityEvidence){
		func(e *auth.SignedValidityEvidence) { e.Issuer = "" }, func(e *auth.SignedValidityEvidence) { e.Environment = "" },
		func(e *auth.SignedValidityEvidence) { e.TokenID = "" }, func(e *auth.SignedValidityEvidence) { e.Tenant = "" }, func(e *auth.SignedValidityEvidence) { e.KeyID = "" },
		func(e *auth.SignedValidityEvidence) { e.Dimensions = nil }, func(e *auth.SignedValidityEvidence) { e.Dimensions = make([]auth.DimensionValidity, 17) },
		func(e *auth.SignedValidityEvidence) { e.Dimensions[0].Dimension.Kind = "unknown" }, func(e *auth.SignedValidityEvidence) { e.Dimensions[0].Dimension.ID = "" }, func(e *auth.SignedValidityEvidence) { e.Dimensions[0].Dimension.Version = 0 },
		func(e *auth.SignedValidityEvidence) { e.Dimensions[0].VerifiedAt = time.Time{} }, func(e *auth.SignedValidityEvidence) { e.Dimensions[0].ValidUntil = e.Dimensions[0].VerifiedAt },
		func(e *auth.SignedValidityEvidence) {
			e.Dimensions[0].VerifiedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			e.Dimensions[0].ValidUntil = e.Dimensions[0].VerifiedAt.Add(time.Second)
		},
	} {
		_, source, _, _, _ := authorityFixture(t)
		mutate(&source.validity)
		if _, err := source.validity.SigningBytes(); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("invalid signed evidence encoding accepted")
		}
	}
}

func TestSignedValidityAcceptsExactMaximumDimensionCount(t *testing.T) {
	_, source, clock, _, _ := authorityFixture(t)
	source.validity.Dimensions = nil
	for i := 0; i < 16; i++ {
		source.validity.Dimensions = append(source.validity.Dimensions, auth.DimensionValidity{Dimension: auth.ValidityDimension{Kind: auth.ValidityOwner, ID: fmt.Sprintf("owner-%d", i), Version: 1}, Active: true, VerifiedAt: clock.Now(), ValidUntil: clock.Now().Add(20 * time.Second)})
	}
	if _, err := source.validity.SigningBytes(); err != nil {
		t.Fatal("inclusive signed dimension limit rejected", err)
	}
}

func TestAccessExpiryDuringBoundedReadDeniesAuthentication(t *testing.T) {
	config, source, clock, key, claims := fixtureConfig(t)
	claims.ExpiresAt = clock.Now().Unix() + 1
	clock.advance(750 * time.Millisecond)
	config.Source = delayedAuthoritySource{source: source, clock: clock, delay: 500 * time.Millisecond}
	a, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, claims)); err == nil {
		t.Fatal("token expired during read but authenticated")
	}
}

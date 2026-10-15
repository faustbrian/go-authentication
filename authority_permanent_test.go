package authentication_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func permanentFixture(t *testing.T) (*auth.AuthorityAuthenticator, *authoritySource, *authorityClock, ed25519.PrivateKey, auth.PermanentAccountProofSpec) {
	t.Helper()
	a, s, clock, key, _ := authorityFixture(t)
	spec := proofSpec()
	spec.Purpose = "permanent-account-upgrade"
	spec.Audience = "resource"
	spec.IssuedAt = clock.Now()
	spec.ExpiresAt = clock.Now().Add(time.Minute)
	proof, _ := auth.NewProof(spec)
	s.record = auth.SignedAuthenticationRecord{Issuer: "https://issuer.example", Environment: "test", State: auth.SignInStateAuthenticated, Permanent: true, Proof: proof, PermanentSubject: "subject", CredentialID: "credential", CredentialVersion: 1, KeyID: "key"}
	resignRecord(t, s, key)
	return a, s, clock, key, auth.PermanentAccountProofSpec{Proof: proof, PermanentSubject: "subject"}
}

func resignRecord(t *testing.T, s *authoritySource, key ed25519.PrivateKey) {
	t.Helper()
	bytes, err := s.record.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	s.record.Signature = ed25519.Sign(key, bytes)
}

func permanentIssuer(t *testing.T, authority *auth.AuthorityAuthenticator) auth.PermanentAccountProofIssuer {
	t.Helper()
	issuer, err := auth.PermanentAccountProofIssuerFromAuthenticator(authority)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func TestPermanentIssuanceRejectsEveryMismatchAndNonPermanentOutcome(t *testing.T) {
	for _, mutate := range []func(*auth.PermanentAccountProofSpec){
		func(s *auth.PermanentAccountProofSpec) { s.PermanentSubject = "" }, func(s *auth.PermanentAccountProofSpec) { s.PermanentSubject = "other" },
		func(s *auth.PermanentAccountProofSpec) { s.Proof.Tenant = "other" }, func(s *auth.PermanentAccountProofSpec) { s.Proof.Subject = "other" },
		func(s *auth.PermanentAccountProofSpec) { s.Proof.Method = "other" }, func(s *auth.PermanentAccountProofSpec) { s.Proof.Assurance = auth.AssuranceMultiFactor },
		func(s *auth.PermanentAccountProofSpec) { s.Proof.Audience = "other" }, func(s *auth.PermanentAccountProofSpec) { s.Proof.Purpose = "other" },
		func(s *auth.PermanentAccountProofSpec) { s.Proof.IssuedAt = s.Proof.IssuedAt.Add(-time.Second) }, func(s *auth.PermanentAccountProofSpec) { s.Proof.ExpiresAt = s.Proof.ExpiresAt.Add(time.Second) },
	} {
		a, _, _, _, spec := permanentFixture(t)
		issuer := permanentIssuer(t, a)
		mutate(&spec)
		if _, err := issuer.IssuePermanentAccountProof(context.Background(), spec); err == nil {
			t.Fatal("permanent proof mismatch accepted")
		}
	}
	for _, mutate := range []func(*auth.SignedAuthenticationRecord){
		func(r *auth.SignedAuthenticationRecord) { r.Issuer = "" }, func(r *auth.SignedAuthenticationRecord) { r.Environment = "" }, func(r *auth.SignedAuthenticationRecord) { r.KeyID = "" },
		func(r *auth.SignedAuthenticationRecord) { r.Permanent = false }, func(r *auth.SignedAuthenticationRecord) { r.State = auth.SignInStateRejected },
		func(r *auth.SignedAuthenticationRecord) { r.State = auth.SignInStateChallengeRequired }, func(r *auth.SignedAuthenticationRecord) { r.PermanentSubject = "other" },
		func(r *auth.SignedAuthenticationRecord) { r.CredentialID = "" }, func(r *auth.SignedAuthenticationRecord) { r.CredentialVersion = 0 },
		func(r *auth.SignedAuthenticationRecord) { r.Proof.Subject = "" }, func(r *auth.SignedAuthenticationRecord) { r.Proof.Purpose = "other" },
		func(r *auth.SignedAuthenticationRecord) {
			r.Proof.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			r.Proof.ExpiresAt = r.Proof.IssuedAt.Add(time.Minute)
		},
	} {
		a, s, _, _, spec := permanentFixture(t)
		issuer := permanentIssuer(t, a)
		mutate(&s.record)
		if _, err := s.record.SigningBytes(); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("invalid original authentication record encoded")
		}
		if _, err := issuer.IssuePermanentAccountProof(context.Background(), spec); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("non-permanent original outcome minted proof")
		}
	}
	for _, mutate := range []func(*auth.SignedAuthenticationRecord){
		func(r *auth.SignedAuthenticationRecord) { r.Issuer = "other" }, func(r *auth.SignedAuthenticationRecord) { r.Environment = "other" }, func(r *auth.SignedAuthenticationRecord) { r.KeyID = "other" },
	} {
		a, s, _, key, spec := permanentFixture(t)
		issuer := permanentIssuer(t, a)
		mutate(&s.record)
		resignRecord(t, s, key)
		if _, err := issuer.IssuePermanentAccountProof(context.Background(), spec); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("other issuer accepted")
		}
	}
	a, s, clock, _, spec := permanentFixture(t)
	issuer := permanentIssuer(t, a)
	s.record.Signature[0] ^= 1
	if _, err := issuer.IssuePermanentAccountProof(context.Background(), spec); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("forged authentication record accepted")
	}
	s.err = errors.New("source outage")
	if _, err := issuer.IssuePermanentAccountProof(context.Background(), spec); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("issuer source outage accepted")
	}
	var absentContext context.Context
	if _, err := issuer.IssuePermanentAccountProof(absentContext, spec); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("issuer nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer.IssuePermanentAccountProof(ctx, spec); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("issuer cancellation accepted")
	}
	clock.advance(time.Minute)
	if _, err := issuer.IssuePermanentAccountProof(context.Background(), spec); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("expired original proof accepted")
	}
}

func TestPermanentProofProjectsOnlyBindingsAndRequiresExpectedAuthority(t *testing.T) {
	a, _, clock, _, spec := permanentFixture(t)
	issuer := permanentIssuer(t, a)
	proof, err := issuer.IssuePermanentAccountProof(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	projection := proof.Bindings()
	projection.Proof.Subject = "changed"
	projection.PermanentSubject = "changed"
	if proof.Bindings().PermanentSubject != "subject" || proof.Bindings().Proof.Subject != "subject" {
		t.Fatal("caller mutation replaced authority bindings")
	}
	use := auth.ProofUse{Tenant: "tenant", Subject: "subject", Purpose: "permanent-account-upgrade", Audience: "resource", Now: clock.Now()}
	if err := a.ValidatePermanentAccountProof(proof, use); err != nil {
		t.Fatal(err)
	}
	use.Purpose = "other"
	if err := a.ValidatePermanentAccountProof(proof, use); !errors.Is(err, auth.ErrProofPurposeMismatch) {
		t.Fatal("cross-purpose permanent proof accepted")
	}
	if err := a.ValidatePermanentAccountProof(auth.PermanentAccountProof{}, use); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("zero authority proof accepted")
	}
	if err := ((*auth.AuthorityAuthenticator)(nil)).ValidatePermanentAccountProof(proof, use); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("nil expected authority accepted")
	}
}

func TestPermanentIssuanceChecksExpiryAfterSourceRead(t *testing.T) {
	config, s, clock, key, _ := fixtureConfig(t)
	spec := proofSpec()
	spec.Purpose = "permanent-account-upgrade"
	spec.Audience = "resource"
	spec.IssuedAt = clock.Now()
	spec.ExpiresAt = clock.Now().Add(time.Second)
	proof, _ := auth.NewProof(spec)
	s.record = auth.SignedAuthenticationRecord{Issuer: config.Issuer, Environment: config.Environment, State: auth.SignInStateAuthenticated, Permanent: true, Proof: proof, PermanentSubject: "subject", CredentialID: "credential", CredentialVersion: 1, KeyID: "key"}
	resignRecord(t, s, key)
	clock.advance(750 * time.Millisecond)
	config.Source = delayedAuthoritySource{source: s, clock: clock, delay: 500 * time.Millisecond}
	a, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	issuer := permanentIssuer(t, a)
	if _, err := issuer.IssuePermanentAccountProof(context.Background(), auth.PermanentAccountProofSpec{Proof: proof, PermanentSubject: "subject"}); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("proof expired during read but minted")
	}
}

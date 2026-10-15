package authentication_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

type signinSource struct {
	*authoritySource
	signin auth.SignedSignInRecord
}

func (s *signinSource) SignInAuthentication(context.Context, auth.ProofID) (auth.SignedSignInRecord, error) {
	return s.signin, s.err
}

func signinFixture(t *testing.T) (auth.AuthorityConfig, *signinSource, *authorityClock, ed25519.PrivateKey, auth.Proof) {
	t.Helper()
	config, source, clock, key, _ := fixtureConfig(t)
	spec := proofSpec()
	spec.Purpose = "session-issue"
	spec.Audience = "resource"
	proof, err := auth.NewProof(spec)
	if err != nil {
		t.Fatal(err)
	}
	signed := &signinSource{authoritySource: source, signin: auth.SignedSignInRecord{
		Issuer: config.Issuer, Environment: config.Environment, State: auth.SignInStateAuthenticated,
		Proof: proof, ProofVersion: 3, CredentialID: "credential", CredentialVersion: 7, KeyID: "key",
	}}
	bytes, err := signed.signin.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	signed.signin.Signature = ed25519.Sign(key, bytes)
	config.Source = signed
	return config, signed, clock, key, proof
}

func TestFinalAuthenticatedProofRequiresExpectedAuthority(t *testing.T) {
	config, _, clock, _, proof := signinFixture(t)
	authority, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := auth.AuthenticatedProofIssuerFromAuthenticator(authority)
	if err != nil {
		t.Fatal(err)
	}
	final, err := issuer.IssueAuthenticatedProof(context.Background(), proof)
	if err != nil {
		t.Fatal(err)
	}
	use := auth.ProofUse{Tenant: proof.Tenant, Subject: proof.Subject, Purpose: "session-issue", Audience: "resource", Now: clock.Now()}
	if err := authority.ValidateAuthenticatedProof(final, use); err != nil {
		t.Fatal(err)
	}
	bindings := final.Bindings()
	if bindings.Proof != proof || bindings.ProofVersion != 3 || bindings.CredentialID != "credential" || bindings.CredentialVersion != 7 {
		t.Fatal("original final authentication linkage changed")
	}
	other, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.ValidateAuthenticatedProof(final, use); err == nil {
		t.Fatal("foreign composition accepted proof")
	}
	bindings.Proof.Subject = "changed"
	bindings.CredentialID = "changed"
	if final.Bindings().Proof != proof || final.Bindings().CredentialID != "credential" {
		t.Fatal("projection replaced private authority")
	}
	for _, use := range []auth.ProofUse{
		{Tenant: "other", Subject: proof.Subject, Purpose: "session-issue", Audience: "resource", Now: clock.Now()},
		{Tenant: proof.Tenant, Subject: "other", Purpose: "session-issue", Audience: "resource", Now: clock.Now()},
		{Tenant: proof.Tenant, Subject: proof.Subject, Purpose: "other", Audience: "resource", Now: clock.Now()},
		{Tenant: proof.Tenant, Subject: proof.Subject, Purpose: "session-issue", Audience: "other", Now: clock.Now()},
		{Tenant: proof.Tenant, Subject: proof.Subject, Purpose: "session-issue", Audience: "resource", Now: proof.ExpiresAt},
	} {
		if authority.ValidateAuthenticatedProof(final, use) == nil {
			t.Fatal("changed use accepted")
		}
	}
	if authority.ValidateAuthenticatedProof(auth.AuthenticatedProof{}, use) == nil || ((*auth.AuthorityAuthenticator)(nil)).ValidateAuthenticatedProof(final, use) == nil {
		t.Fatal("zero proof or authority accepted")
	}
	var zero auth.AuthorityAuthenticator
	if zero.ValidateAuthenticatedProof(final, use) == nil || (auth.AuthenticatedProof{}).Bindings() != (auth.AuthenticatedProofSpec{}) {
		t.Fatal("zero metadata accepted")
	}
	for _, p := range []auth.AuthenticatedProof{final, {}} {
		if _, err := json.Marshal(p); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("proof JSON disclosure")
		}
		if _, err := p.MarshalText(); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("proof text disclosure")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, p), "credential") || strings.Contains(fmt.Sprintf(verb, p), string(proof.ID)) {
				t.Fatal("proof formatting disclosure")
			}
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				if authority.ValidateAuthenticatedProof(final, use) != nil {
					t.Error("concurrent proof invalid")
				}
			}
		}()
	}
	wg.Wait()
}

func TestFinalAuthenticationRejectsIncompleteForgedAndDifferentOriginalRecords(t *testing.T) {
	for _, mutate := range []func(*auth.SignedSignInRecord){
		func(r *auth.SignedSignInRecord) { r.Issuer = "" }, func(r *auth.SignedSignInRecord) { r.Environment = "" },
		func(r *auth.SignedSignInRecord) { r.State = auth.SignInStateChallengeRequired }, func(r *auth.SignedSignInRecord) { r.State = auth.SignInStateRejected },
		func(r *auth.SignedSignInRecord) { r.ProofVersion = 0 }, func(r *auth.SignedSignInRecord) { r.CredentialID = "" }, func(r *auth.SignedSignInRecord) { r.CredentialVersion = 0 },
		func(r *auth.SignedSignInRecord) { r.KeyID = "" }, func(r *auth.SignedSignInRecord) { r.Proof.Purpose = "permanent-account-upgrade" }, func(r *auth.SignedSignInRecord) { r.Proof.ID = "" },
		func(r *auth.SignedSignInRecord) {
			r.Proof.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			r.Proof.ExpiresAt = r.Proof.IssuedAt.Add(time.Minute)
		},
	} {
		config, s, _, _, requested := signinFixture(t)
		mutate(&s.signin)
		if _, err := s.signin.SigningBytes(); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("malformed original framed")
		}
		a, _ := auth.NewAuthorityAuthenticator(config)
		issuer, _ := auth.AuthenticatedProofIssuerFromAuthenticator(a)
		if p, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrInvalidProof) || p != (auth.AuthenticatedProof{}) {
			t.Fatal("malformed original minted proof")
		}
	}
	for _, mutate := range []func(*auth.SignedSignInRecord){
		func(r *auth.SignedSignInRecord) { r.Issuer = "other" }, func(r *auth.SignedSignInRecord) { r.Environment = "other" }, func(r *auth.SignedSignInRecord) { r.KeyID = "other" },
		func(r *auth.SignedSignInRecord) { r.Proof.Subject = "other" }, func(r *auth.SignedSignInRecord) { r.Proof.Tenant = "other" }, func(r *auth.SignedSignInRecord) { r.Proof.Method = "other" },
		func(r *auth.SignedSignInRecord) { r.Proof.Assurance = auth.AssuranceMultiFactor }, func(r *auth.SignedSignInRecord) { r.Proof.Audience = "other" }, func(r *auth.SignedSignInRecord) { r.Proof.ID = "zyxwvutsrqponmlkjihgfe" },
		func(r *auth.SignedSignInRecord) { r.Proof.ExpiresAt = r.Proof.ExpiresAt.Add(time.Second) }, func(r *auth.SignedSignInRecord) { r.Proof.IssuedAt = r.Proof.IssuedAt.Add(-time.Second) },
	} {
		config, s, _, key, requested := signinFixture(t)
		mutate(&s.signin)
		b, err := s.signin.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		s.signin.Signature = ed25519.Sign(key, b)
		a, _ := auth.NewAuthorityAuthenticator(config)
		issuer, _ := auth.AuthenticatedProofIssuerFromAuthenticator(a)
		if p, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrInvalidProof) || p != (auth.AuthenticatedProof{}) {
			t.Fatal("different signed original accepted")
		}
	}
	for _, mutate := range []func(*auth.SignedSignInRecord){
		func(r *auth.SignedSignInRecord) { r.Signature = nil }, func(r *auth.SignedSignInRecord) { r.Signature[0] ^= 1 }, func(r *auth.SignedSignInRecord) { r.ProofVersion++ }, func(r *auth.SignedSignInRecord) { r.CredentialID = "changed" }, func(r *auth.SignedSignInRecord) { r.CredentialVersion++ },
	} {
		config, s, _, _, requested := signinFixture(t)
		mutate(&s.signin)
		a, _ := auth.NewAuthorityAuthenticator(config)
		issuer, _ := auth.AuthenticatedProofIssuerFromAuthenticator(a)
		if p, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrInvalidProof) || p != (auth.AuthenticatedProof{}) {
			t.Fatal("forged original accepted")
		}
	}
}

type delayedSigninSource struct {
	*signinSource
	clock  *authorityClock
	delay  time.Duration
	cancel context.CancelFunc
}

func (s delayedSigninSource) SignInAuthentication(ctx context.Context, id auth.ProofID) (auth.SignedSignInRecord, error) {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
		return auth.SignedSignInRecord{}, errors.New("unbounded source")
	}
	s.clock.advance(s.delay)
	if s.cancel != nil {
		s.cancel()
	}
	return s.signinSource.SignInAuthentication(ctx, id)
}

func TestFinalAuthenticationHonorsCancellationOutageAndOriginalExpiryAfterRead(t *testing.T) {
	config, s, clock, _, requested := signinFixture(t)
	a, _ := auth.NewAuthorityAuthenticator(config)
	issuer, _ := auth.AuthenticatedProofIssuerFromAuthenticator(a)
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		if p, err := issuer.IssueAuthenticatedProof(ctx, requested); !errors.Is(err, auth.ErrAuthenticationUnavailable) || p != (auth.AuthenticatedProof{}) {
			t.Fatal("cancelled ingress accepted")
		}
	}
	s.err = errors.New("sensitive source outage")
	if _, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrAuthenticationUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("outage not redacted")
	}
	s.err = nil
	bad := requested
	bad.Purpose = "other"
	if _, err := issuer.IssueAuthenticatedProof(context.Background(), bad); !errors.Is(err, auth.ErrProofPurposeMismatch) {
		t.Fatal("wrong requested purpose accepted")
	}
	clock.advance(requested.ExpiresAt.Sub(clock.Now()))
	if _, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("expiry equality accepted")
	}
	for _, delay := range []time.Duration{-time.Millisecond, 2 * time.Second} {
		config, s, clock, _, requested = signinFixture(t)
		config.Source = delayedSigninSource{signinSource: s, clock: clock, delay: delay}
		a, _ = auth.NewAuthorityAuthenticator(config)
		issuer, _ = auth.AuthenticatedProofIssuerFromAuthenticator(a)
		if _, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
			t.Fatal("read clock budget ignored")
		}
	}
	config, s, clock, _, requested = signinFixture(t)
	clock.advance(requested.ExpiresAt.Sub(clock.Now()) - time.Millisecond)
	config.Source = delayedSigninSource{signinSource: s, clock: clock, delay: time.Millisecond}
	// Original signed expiry remains unchanged, including after a successful read.
	a, _ = auth.NewAuthorityAuthenticator(config)
	issuer, _ = auth.AuthenticatedProofIssuerFromAuthenticator(a)
	if _, err := issuer.IssueAuthenticatedProof(context.Background(), requested); !errors.Is(err, auth.ErrExpiredProof) {
		t.Fatal("read renewed expiry")
	}
	config, s, clock, _, requested = signinFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config.Source = delayedSigninSource{signinSource: s, clock: clock, cancel: cancel}
	a, _ = auth.NewAuthorityAuthenticator(config)
	issuer, _ = auth.AuthenticatedProofIssuerFromAuthenticator(a)
	if _, err := issuer.IssueAuthenticatedProof(ctx, requested); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("cancelled read minted proof")
	}
}

func TestFinalProofFactoryRejectsExternalAndLegacyCompositions(t *testing.T) {
	for _, a := range []auth.Authenticator{nil, (*auth.AuthorityAuthenticator)(nil), &auth.AuthorityAuthenticator{}, &externalAuthority{}} {
		if _, err := auth.AuthenticatedProofIssuerFromAuthenticator(a); !errors.Is(err, auth.ErrInvalidConfiguration) {
			t.Fatal("external factory accepted")
		}
	}
	a, _, _, _, _ := authorityFixture(t)
	if _, err := auth.AuthenticatedProofIssuerFromAuthenticator(a); !errors.Is(err, auth.ErrInvalidConfiguration) {
		t.Fatal("legacy source granted final proof")
	}
}

func TestSignedSignInFrameConservesTimeAndExcludesSignature(t *testing.T) {
	_, s, _, _, _ := signinFixture(t)
	original, err := s.signin.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	r := s.signin
	r.Signature = []byte("not part of the signing frame")
	r.Proof.IssuedAt = r.Proof.IssuedAt.In(time.FixedZone("source", 3600))
	r.Proof.ExpiresAt = r.Proof.ExpiresAt.In(time.FixedZone("source", 3600))
	normalized, err := r.SigningBytes()
	if err != nil || string(original) != string(normalized) {
		t.Fatal("frame changed an instant or included the signature")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		formatted := fmt.Sprintf(verb, r)
		if strings.Contains(formatted, string(r.Proof.ID)) || strings.Contains(formatted, r.CredentialID) || strings.Contains(formatted, "not part") {
			t.Fatal("original record disclosed")
		}
	}
}

func FuzzSignedSignInRecordBounds(f *testing.F) {
	for _, input := range []string{"credential", "", "\n", "\u0085", strings.Repeat("a", 257)} {
		f.Add(input, uint8(auth.SignInStateAuthenticated), uint64(1))
	}
	f.Fuzz(func(t *testing.T, credential string, state uint8, version uint64) {
		p := auth.Proof(proofSpec())
		p.Purpose = "session-issue"
		r := auth.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: auth.SignInState(state), Proof: p, ProofVersion: 1, CredentialID: credential, CredentialVersion: version, KeyID: "key"}
		b, err := r.SigningBytes()
		if err != nil {
			if !errors.Is(err, auth.ErrInvalidProof) || b != nil {
				t.Fatal("partial or non-redacted frame")
			}
			return
		}
		if len(b) > 4096 || state != uint8(auth.SignInStateAuthenticated) || version == 0 || len(credential) == 0 || len(credential) > 256 {
			t.Fatal("unbounded or non-final frame")
		}
		if !strings.HasPrefix(string(b), "golib/shared-issuer-v1/signin-authentication\x00") {
			t.Fatal("wrong signing domain")
		}
	})
}

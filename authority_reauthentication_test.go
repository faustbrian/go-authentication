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

type reauthenticationSource struct {
	*authoritySource
	record auth.SignedReauthenticationRecord
	read   func(context.Context)
}

func (s *reauthenticationSource) Reauthentication(ctx context.Context, _ auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	if s.read != nil {
		s.read(ctx)
	}
	return s.record, s.err
}

func TestReauthenticationAuthorityBoundsSourceRead(t *testing.T) {
	for _, scenario := range []string{"freshness", "timeout", "backwards", "panic"} {
		t.Run(scenario, func(t *testing.T) {
			a, source, clock, p, use := reauthenticationFixture(t)
			use.MaximumAge = clock.Now().Sub(p.Proof.IssuedAt) + 500*time.Millisecond
			source.read = func(ctx context.Context) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("source read unbounded")
				}
				switch scenario {
				case "freshness":
					clock.advance(500 * time.Millisecond)
				case "timeout":
					clock.advance(2 * time.Second)
				case "backwards":
					clock.advance(-time.Second)
				case "panic":
					panic("private provider diagnostics")
				}
			}
			err := a.ValidateReauthenticationProof(context.Background(), p, use)
			if err == nil {
				t.Fatal("source read reset freshness or exceeded bound")
			}
			if scenario != "freshness" && !errors.Is(err, auth.ErrAuthenticationUnavailable) {
				t.Fatal("source failure classification lost")
			}
		})
	}
}

func TestReauthenticationAuthorityRejectsMissingSignatureAndLegacySource(t *testing.T) {
	a, source, _, p, use := reauthenticationFixture(t)
	source.record.Signature = nil
	if !errors.Is(a.ValidateReauthenticationProof(context.Background(), p, use), auth.ErrInvalidProof) {
		t.Fatal("unsigned original accepted")
	}
	config, _, _, _, _ := fixtureConfig(t)
	legacy, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(legacy.ValidateReauthenticationProof(context.Background(), p, use), auth.ErrInvalidConfiguration) {
		t.Fatal("legacy source minted authority")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
		if output := fmt.Sprintf(verb, source.record); strings.Contains(output, string(p.Proof.ID)) || strings.Contains(output, source.record.CredentialID) {
			t.Fatal("diagnostic disclosed original")
		}
	}
}

func TestReauthenticationAuthorityRequiresSignedOriginalAndExactUse(t *testing.T) {
	a, source, _, p, use := reauthenticationFixture(t)
	if err := a.ValidateReauthenticationProof(context.Background(), p, use); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*auth.ReauthenticationProof){
		func(p *auth.ReauthenticationProof) { p.SessionVersion++ },
		func(p *auth.ReauthenticationProof) { p.Proof.ID = "abcdefghijklmnopqrstuw" },
		func(p *auth.ReauthenticationProof) { p.Action = "other" },
	} {
		changed := p
		mutate(&changed)
		if a.ValidateReauthenticationProof(context.Background(), changed, use) == nil {
			t.Fatal("manufactured proof accepted")
		}
	}
	source.record.CredentialVersion++
	if !errors.Is(a.ValidateReauthenticationProof(context.Background(), p, use), auth.ErrInvalidProof) {
		t.Fatal("unsigned credential change accepted")
	}
	source.err = errors.New("private storage failure")
	if !errors.Is(a.ValidateReauthenticationProof(context.Background(), p, use), auth.ErrAuthenticationUnavailable) {
		t.Fatal("source outage accepted")
	}
}

func reauthenticationFixture(t *testing.T) (*auth.AuthorityAuthenticator, *reauthenticationSource, *authorityClock, auth.ReauthenticationProof, auth.ReauthenticationUse) {
	t.Helper()
	config, original, clock, key, _ := fixtureConfig(t)
	proof, err := auth.NewProof(proofSpec())
	if err != nil {
		t.Fatal(err)
	}
	proof.Audience = config.Audience
	proof.Purpose = "identity.password.change"
	p := auth.ReauthenticationProof{Proof: proof, SessionID: "session", SessionVersion: 2, Action: "identity.password.change"}
	source := &reauthenticationSource{authoritySource: original, record: auth.SignedReauthenticationRecord{
		Issuer: config.Issuer, Environment: config.Environment, Proof: p, ProofVersion: 3,
		CredentialID: "password", CredentialVersion: 7, KeyID: "key",
	}}
	frame, err := source.record.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	source.record.Signature = ed25519.Sign(key, frame)
	config.Source = source
	a, err := auth.NewAuthorityAuthenticator(config)
	if err != nil {
		t.Fatal(err)
	}
	use := auth.ReauthenticationUse{ProofUse: auth.ProofUse{Tenant: proof.Tenant, Subject: proof.Subject, Purpose: proof.Purpose, Audience: config.Audience, Now: clock.Now()}, SessionID: "session", SessionVersion: 2, Action: string(proof.Purpose), MaximumAge: time.Minute}
	return a, source, clock, p, use
}

func TestReauthenticationAuthorityScopeClockAndZeroDenial(t *testing.T) {
	audienceAuthority, _, _, audienceProof, audienceUse := reauthenticationFixture(t)
	audienceUse.ProofUse.Audience = "other"
	if !errors.Is(audienceAuthority.ValidateReauthenticationProof(context.Background(), audienceProof, audienceUse), auth.ErrProofAudienceMismatch) {
		t.Fatal("audience denial lost its public error category")
	}
	for name, mutate := range map[string]func(*auth.ReauthenticationUse){
		"tenant":       func(u *auth.ReauthenticationUse) { u.ProofUse.Tenant = "other" },
		"subject":      func(u *auth.ReauthenticationUse) { u.ProofUse.Subject = "other" },
		"purpose":      func(u *auth.ReauthenticationUse) { u.ProofUse.Purpose = "other" },
		"audience":     func(u *auth.ReauthenticationUse) { u.ProofUse.Audience = "other" },
		"session":      func(u *auth.ReauthenticationUse) { u.SessionID = "other" },
		"version":      func(u *auth.ReauthenticationUse) { u.SessionVersion++ },
		"action":       func(u *auth.ReauthenticationUse) { u.Action = "other" },
		"age":          func(u *auth.ReauthenticationUse) { u.MaximumAge = 0 },
		"negative-age": func(u *auth.ReauthenticationUse) { u.MaximumAge = -time.Second },
		"excess-age":   func(u *auth.ReauthenticationUse) { u.MaximumAge = 25 * time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			a, _, _, p, use := reauthenticationFixture(t)
			mutate(&use)
			if a.ValidateReauthenticationProof(context.Background(), p, use) == nil {
				t.Fatal("different use accepted")
			}
		})
	}
	a, _, clock, p, use := reauthenticationFixture(t)
	use.ProofUse.Now = p.Proof.IssuedAt.Add(-time.Hour)
	if a.ValidateReauthenticationProof(context.Background(), p, use) != nil {
		t.Fatal("caller clock controlled authority")
	}
	clock.advance(use.MaximumAge)
	if a.ValidateReauthenticationProof(context.Background(), p, use) == nil {
		t.Fatal("expired freshness revived with caller clock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(a.ValidateReauthenticationProof(ctx, p, use), context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if a.ValidateReauthenticationProof(nil, p, use) == nil || ((*auth.AuthorityAuthenticator)(nil)).ValidateReauthenticationProof(context.Background(), p, use) == nil {
		t.Fatal("zero authority accepted")
	}
}

func TestReauthenticationSigningFrameRejectsMalformedOriginal(t *testing.T) {
	for name, mutate := range map[string]func(*auth.SignedReauthenticationRecord){
		"issuer":             func(r *auth.SignedReauthenticationRecord) { r.Issuer = "" },
		"environment":        func(r *auth.SignedReauthenticationRecord) { r.Environment = "" },
		"proof-version":      func(r *auth.SignedReauthenticationRecord) { r.ProofVersion = 0 },
		"credential":         func(r *auth.SignedReauthenticationRecord) { r.CredentialID = "" },
		"credential-version": func(r *auth.SignedReauthenticationRecord) { r.CredentialVersion = 0 },
		"key":                func(r *auth.SignedReauthenticationRecord) { r.KeyID = "" },
		"session":            func(r *auth.SignedReauthenticationRecord) { r.Proof.SessionVersion = 0 },
		"expiry":             func(r *auth.SignedReauthenticationRecord) { r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			_, source, _, _, _ := reauthenticationFixture(t)
			mutate(&source.record)
			if frame, err := source.record.SigningBytes(); len(frame) != 0 || !errors.Is(err, auth.ErrInvalidProof) {
				t.Fatal("malformed original signed")
			}
		})
	}
}

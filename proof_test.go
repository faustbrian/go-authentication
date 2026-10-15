package authentication_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestPurposeRejectsUnboundedOrNonCanonicalInput(t *testing.T) {
	for _, input := range []string{"", "with space", "é", "\x00"} {
		if _, err := auth.NewPurpose(input); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("invalid purpose accepted")
		}
	}
	if purpose, err := auth.NewPurpose("permanent-account-upgrade"); err != nil || purpose != "permanent-account-upgrade" {
		t.Fatal("canonical purpose rejected")
	}
}

func TestOpaqueCodesBoundAndDoNotDisclose(t *testing.T) {
	for _, n := range []int{3, 129} {
		if _, err := auth.NewOneTimeCode(strings.Repeat("A", n)); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("code bound accepted")
		}
	}
	for _, n := range []int{7, 257} {
		if _, err := auth.NewRecoveryCode(strings.Repeat("A", n)); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("recovery bound accepted")
		}
	}
	for _, input := range []string{"123\n", "123é", "123\x00"} {
		if _, err := auth.NewOneTimeCode(input); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("hostile code accepted")
		}
	}
	secret := "A-secret-value-123"
	one, err := auth.NewOneTimeCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := auth.NewRecoveryCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{one, &one, recovery, &recovery} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(format, value), secret) {
				t.Fatal("formatted secret disclosed")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), secret) {
			t.Fatal("JSON disclosed secret")
		}
		if _, ok := value.(fmt.Stringer); ok {
			t.Fatal("secret has string conversion")
		}
	}
}

func proofSpec() auth.ProofSpec {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return auth.ProofSpec{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "subject", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "operation", Audience: "service", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func proofUse() auth.ProofUse {
	spec := proofSpec()
	return auth.ProofUse{Tenant: spec.Tenant, Subject: spec.Subject, Purpose: spec.Purpose, Audience: spec.Audience, Now: spec.IssuedAt.Add(time.Minute)}
}

func TestProofRejectsUnicodeControlsInEveryIdentityBinding(t *testing.T) {
	for _, field := range []struct {
		name   string
		assign func(*auth.ProofSpec, string)
	}{
		{"tenant", func(s *auth.ProofSpec, value string) { s.Tenant = value }},
		{"subject", func(s *auth.ProofSpec, value string) { s.Subject = value }},
		{"method", func(s *auth.ProofSpec, value string) { s.Method = value }},
		{"audience", func(s *auth.ProofSpec, value string) { s.Audience = value }},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []string{"printable-é-日本", "boundary-\u00a0"} {
				spec := proofSpec()
				field.assign(&spec, value)
				proof, err := auth.NewProof(spec)
				if err != nil || proof != auth.Proof(spec) {
					t.Fatal("printable Unicode identity rejected or changed")
				}
			}
			for control := rune(0x7f); control <= 0x9f; control++ {
				t.Run(fmt.Sprintf("U+%04X", control), func(t *testing.T) {
					spec := proofSpec()
					field.assign(&spec, "identity-"+string(control))
					proof, err := auth.NewProof(spec)
					if !errors.Is(err, auth.ErrInvalidProof) || proof != (auth.Proof{}) {
						t.Fatal("Unicode control admitted or usable proof returned")
					}
				})
			}
		})
	}
}

func TestProofBindsEveryUseAndRejectsInvalidConstruction(t *testing.T) {
	proof, err := auth.NewProof(proofSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Validate(proofUse()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*auth.ProofSpec){
		func(s *auth.ProofSpec) { s.ID = "short" }, func(s *auth.ProofSpec) { s.ID = auth.ProofID(strings.Repeat("a", 129)) },
		func(s *auth.ProofSpec) { s.Tenant = "" }, func(s *auth.ProofSpec) { s.Subject = "" }, func(s *auth.ProofSpec) { s.Method = "" }, func(s *auth.ProofSpec) { s.Audience = "" },
		func(s *auth.ProofSpec) { s.Subject = strings.Repeat("a", 257) }, func(s *auth.ProofSpec) { s.Subject = "\xff" }, func(s *auth.ProofSpec) { s.Purpose = "" },
		func(s *auth.ProofSpec) { s.Assurance = auth.AssuranceUnspecified }, func(s *auth.ProofSpec) { s.Assurance = auth.Assurance(99) },
		func(s *auth.ProofSpec) { s.IssuedAt = time.Time{} }, func(s *auth.ProofSpec) { s.ExpiresAt = s.IssuedAt }, func(s *auth.ProofSpec) { s.ExpiresAt = s.IssuedAt.Add(24*time.Hour + 1) },
	} {
		spec := proofSpec()
		mutate(&spec)
		if _, err := auth.NewProof(spec); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("invalid proof accepted")
		}
	}
	for _, tc := range []struct {
		mutate func(*auth.ProofUse)
		want   error
	}{
		{func(u *auth.ProofUse) { u.Tenant = "other" }, auth.ErrInvalidProof}, {func(u *auth.ProofUse) { u.Subject = "other" }, auth.ErrInvalidProof},
		{func(u *auth.ProofUse) { u.Purpose = "other" }, auth.ErrProofPurposeMismatch}, {func(u *auth.ProofUse) { u.Audience = "other" }, auth.ErrProofAudienceMismatch},
		{func(u *auth.ProofUse) { u.Now = proof.ExpiresAt }, auth.ErrExpiredProof}, {func(u *auth.ProofUse) { u.Now = proof.IssuedAt.Add(-1) }, auth.ErrInvalidProof},
	} {
		use := proofUse()
		tc.mutate(&use)
		if err := proof.Validate(use); !errors.Is(err, tc.want) {
			t.Fatalf("want %v got %v", tc.want, err)
		}
	}
}

func TestReauthenticationAndRecoveryAreExactClosedUses(t *testing.T) {
	proof, _ := auth.NewProof(proofSpec())
	reauth := auth.ReauthenticationProof{Proof: proof, SessionID: "session", SessionVersion: 1, Action: "delete"}
	use := auth.ReauthenticationUse{ProofUse: proofUse(), SessionID: "session", SessionVersion: 1, Action: "delete", MaximumAge: 2 * time.Minute}
	if err := reauth.Validate(use); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*auth.ReauthenticationUse){func(u *auth.ReauthenticationUse) { u.SessionID = "other" }, func(u *auth.ReauthenticationUse) { u.SessionVersion = 2 }, func(u *auth.ReauthenticationUse) { u.Action = "other" }, func(u *auth.ReauthenticationUse) { u.MaximumAge = 0 }, func(u *auth.ReauthenticationUse) { u.MaximumAge = time.Second }} {
		bad := use
		mutate(&bad)
		if err := reauth.Validate(bad); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("reauth mismatch accepted")
		}
	}
	union := auth.ReauthenticationOrRecoveryProof{Kind: auth.ProofKindReauthentication, Reauthentication: reauth}
	if err := union.Validate(use, false); err != nil {
		t.Fatal(err)
	}
	union.Recovery = proof
	if err := union.Validate(use, true); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("two arms accepted")
	}
	union = auth.ReauthenticationOrRecoveryProof{Kind: auth.ProofKindRecovery, Recovery: proof}
	if err := union.Validate(use, false); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("unauthorized recovery accepted")
	}
	if err := union.Validate(use, true); err != nil {
		t.Fatal(err)
	}
	union.Reauthentication.SessionVersion = 1
	if err := union.Validate(use, true); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("recovery with populated inactive arm accepted")
	}
	if err := (auth.ReauthenticationOrRecoveryProof{}).Validate(use, true); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("zero union accepted")
	}
	reauth.Proof = auth.Proof{}
	if err := reauth.Validate(use); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("invalid embedded proof accepted")
	}
}

func TestProofValidationConcurrentWithoutSharedMutation(t *testing.T) {
	proof, _ := auth.NewProof(proofSpec())
	use := proofUse()
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 100 {
				if err := proof.Validate(use); err != nil {
					t.Error(err)
				}
			}
		})
	}
	workers.Wait()
}

func TestProofConstructorExactByteAndTimeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name             string
		assign           func(*auth.ProofSpec, string)
		minimum, maximum int
	}{
		{"identity", func(s *auth.ProofSpec, v string) { s.ID = auth.ProofID(v) }, 22, 128},
		{"purpose", func(s *auth.ProofSpec, v string) { s.Purpose = auth.Purpose(v) }, 1, 128},
		{"tenant", func(s *auth.ProofSpec, v string) { s.Tenant = v }, 1, 256},
		{"subject", func(s *auth.ProofSpec, v string) { s.Subject = v }, 1, 256},
		{"method", func(s *auth.ProofSpec, v string) { s.Method = v }, 1, 256},
		{"audience", func(s *auth.ProofSpec, v string) { s.Audience = v }, 1, 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, n := range []int{tc.minimum - 1, tc.minimum, tc.maximum, tc.maximum + 1} {
				spec := proofSpec()
				tc.assign(&spec, strings.Repeat("a", n))
				_, err := auth.NewProof(spec)
				if (err == nil) != (n >= tc.minimum && n <= tc.maximum) {
					t.Fatalf("wrong bound for %d bytes", n)
				}
			}
		})
	}
	for _, lifetime := range []time.Duration{-1, 0, 1, 24 * time.Hour, 24*time.Hour + 1} {
		spec := proofSpec()
		spec.ExpiresAt = spec.IssuedAt.Add(lifetime)
		_, err := auth.NewProof(spec)
		if (err == nil) != (lifetime > 0 && lifetime <= 24*time.Hour) {
			t.Fatalf("wrong lifetime bound: %v", lifetime)
		}
	}
	proof, _ := auth.NewProof(proofSpec())
	for _, mutate := range []func(*auth.ProofUse){func(u *auth.ProofUse) { u.Now = time.Time{} }, func(u *auth.ProofUse) { u.Tenant = "" }, func(u *auth.ProofUse) { u.Subject = "" }, func(u *auth.ProofUse) { u.Audience = "" }, func(u *auth.ProofUse) { u.Purpose = "" }} {
		use := proofUse()
		mutate(&use)
		if err := proof.Validate(use); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("incomplete use accepted")
		}
	}
	proof.Tenant = ""
	if err := proof.Validate(proofUse()); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("literal-mutated proof bypassed validation")
	}
}

func TestReauthenticationFreshnessAndSessionBoundaries(t *testing.T) {
	proof, _ := auth.NewProof(proofSpec())
	valid := auth.ReauthenticationProof{Proof: proof, SessionID: "session", SessionVersion: 1, Action: "action"}
	use := auth.ReauthenticationUse{ProofUse: proofUse(), SessionID: valid.SessionID, SessionVersion: 1, Action: valid.Action, MaximumAge: time.Hour}
	for _, mutate := range []func(*auth.ReauthenticationProof){
		func(p *auth.ReauthenticationProof) { p.SessionID = "" }, func(p *auth.ReauthenticationProof) { p.SessionID = strings.Repeat("a", 129) },
		func(p *auth.ReauthenticationProof) { p.Action = "" }, func(p *auth.ReauthenticationProof) { p.Action = strings.Repeat("a", 129) }, func(p *auth.ReauthenticationProof) { p.SessionVersion = 0 },
	} {
		bad := valid
		mutate(&bad)
		matchingInvalidUse := use
		matchingInvalidUse.SessionID, matchingInvalidUse.SessionVersion, matchingInvalidUse.Action = bad.SessionID, bad.SessionVersion, bad.Action
		if err := bad.Validate(matchingInvalidUse); !errors.Is(err, auth.ErrInvalidProof) {
			t.Fatal("invalid session proof accepted")
		}
	}
	for _, age := range []time.Duration{-1, 0, time.Minute - 1, time.Minute, time.Minute + 1, 24 * time.Hour, 24*time.Hour + 1} {
		use.MaximumAge = age
		err := valid.Validate(use)
		if (err == nil) != (age > time.Minute && age <= 24*time.Hour) {
			t.Fatalf("wrong freshness at %v: %v", age, err)
		}
	}
}

package authentication_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func resignValidity(t *testing.T, s *authoritySource, key ed25519.PrivateKey) {
	t.Helper()
	bytes, err := s.validity.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	s.validity.Signature = ed25519.Sign(key, bytes)
}

func sizedAccessToken(t *testing.T, key ed25519.PrivateKey, claims auth.AccessTokenClaims, size int) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for headerPadding := 0; headerPadding < 3; headerPadding++ {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"at+jwt","kid":"key"}` + strings.Repeat(" ", headerPadding)))
		for adjustment := -2; adjustment <= 2; adjustment++ {
			padding := (size-len(header)-88)*3/4 + adjustment - len(payload)
			if padding < 0 {
				continue
			}
			encoded := base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), payload...), []byte(strings.Repeat(" ", padding))...))
			if len(header)+len(encoded)+88 != size {
				continue
			}
			prefix := header + "." + encoded
			return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		}
	}
	t.Fatal("unable to construct exact compact boundary")
	return ""
}

func TestAccessTokenExactByteLimitAndHeaderErrorClassification(t *testing.T) {
	a, _, _, key, claims := authorityFixture(t)
	if _, err := a.ValidateAccessToken(context.Background(), sizedAccessToken(t, key, claims, 16384)); err != nil {
		t.Fatal("inclusive token limit rejected", err)
	}
	if _, err := a.ValidateAccessToken(context.Background(), sizedAccessToken(t, key, claims, 16385)); !errors.Is(err, auth.ErrCredentialsInvalid) {
		t.Fatal("oversized signed token not classified invalid")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{`{"alg":"none","typ":"at+jwt","kid":"key"}`, `{"alg":"EdDSA","typ":"JWT","kid":"key"}`, `{"alg":"EdDSA","typ":"at+jwt","kid":""}`, `{"alg":"EdDSA","typ":"at+jwt","kid":"key","extra":true}`} {
		prefix := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(payload)
		token := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		if _, err := a.ValidateAccessToken(context.Background(), token); !errors.Is(err, auth.ErrCredentialsInvalid) {
			t.Fatal("invalid signed header not classified invalid")
		}
	}
}
func TestSharedIssuerRejectsEveryChangedAuthorityBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*auth.AccessTokenClaims)
	}{
		{"issuer", func(c *auth.AccessTokenClaims) { c.Issuer = "other" }}, {"environment", func(c *auth.AccessTokenClaims) { c.Environment = "other" }},
		{"audience", func(c *auth.AccessTokenClaims) { c.Audience = "other" }}, {"ID-token", func(c *auth.AccessTokenClaims) { c.Purpose = "id-token" }},
		{"missing-subject", func(c *auth.AccessTokenClaims) { c.Subject = "" }}, {"changed-subject", func(c *auth.AccessTokenClaims) { c.Subject = "other" }},
		{"owner-kind", func(c *auth.AccessTokenClaims) { c.Owner.Kind = "unknown" }}, {"workload-only", func(c *auth.AccessTokenClaims) { c.Owner.Kind = auth.AuthorityOwnerWorkload }},
		{"owner-version", func(c *auth.AccessTokenClaims) { c.Owner.Version = 0 }}, {"owner-id", func(c *auth.AccessTokenClaims) { c.Owner.ID = "" }},
		{"tenant", func(c *auth.AccessTokenClaims) { c.Tenant = "other" }}, {"tenant-version", func(c *auth.AccessTokenClaims) { c.TenantVersion = 2 }},
		{"caller", func(c *auth.AccessTokenClaims) { c.ClientID = "other" }}, {"caller-version", func(c *auth.AccessTokenClaims) { c.ClientVersion = 2 }},
		{"signing-version", func(c *auth.AccessTokenClaims) { c.SigningVersion = 2 }}, {"token-id", func(c *auth.AccessTokenClaims) { c.TokenID = "abcdefghijklmnopqrstuw" }},
		{"missing-root", func(c *auth.AccessTokenClaims) { c.RootGrant = auth.AuthorityGrant{} }}, {"root-version", func(c *auth.AccessTokenClaims) { c.RootCredential.Version = 2 }},
		{"expiry", func(c *auth.AccessTokenClaims) { c.ExpiresAt = c.IssuedAt }}, {"lifetime", func(c *auth.AccessTokenClaims) { c.ExpiresAt = c.IssuedAt + 301 }},
		{"future", func(c *auth.AccessTokenClaims) { c.IssuedAt += 10 }}, {"expired", func(c *auth.AccessTokenClaims) { c.IssuedAt -= 100; c.ExpiresAt = c.IssuedAt + 60 }},
		{"missing-required-scope", func(c *auth.AccessTokenClaims) { c.Scopes = []string{"other"} }}, {"duplicate-scope", func(c *auth.AccessTokenClaims) { c.Scopes = []string{"read", "read"} }},
		{"empty-scope", func(c *auth.AccessTokenClaims) { c.Scopes = []string{""} }}, {"oversized-scopes", func(c *auth.AccessTokenClaims) { c.Scopes = make([]string, 129) }},
		{"missing-actor-membership", func(c *auth.AccessTokenClaims) {
			c.Actor = &auth.AuthorityOwner{Kind: auth.AuthorityOwnerUser, ID: "human", Version: 1}
		}},
		{"orphan-membership", func(c *auth.AccessTokenClaims) { c.MembershipID = "membership" }},
		{"root-cycle", func(c *auth.AccessTokenClaims) { c.RootGrant.ID = c.TokenID }},
		{"finite-root-expiry", func(c *auth.AccessTokenClaims) { c.RootCredential.ExpiresAt = time.Unix(c.ExpiresAt-1, 0) }},
		{"too-deep", func(c *auth.AccessTokenClaims) { c.Parents = make([]auth.AuthorityGrant, 5) }},
		{"parent-cycle", func(c *auth.AccessTokenClaims) {
			c.Parents = []auth.AuthorityGrant{{ID: c.TokenID, Version: 1, ExpiresAt: time.Unix(c.ExpiresAt, 0)}}
		}},
		{"missing-parent-expiry", func(c *auth.AccessTokenClaims) { c.Parents = []auth.AuthorityGrant{{ID: "parent", Version: 1}} }},
		{"widened-parent-expiry", func(c *auth.AccessTokenClaims) {
			c.Parents = []auth.AuthorityGrant{{ID: "parent", Version: 1, ExpiresAt: c.RootGrant.ExpiresAt.Add(1)}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _, key, c := authorityFixture(t)
			tc.mutate(&c)
			if _, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, c)); err == nil {
				t.Fatal("changed authority accepted")
			}
		})
	}
}

func TestSharedIssuerPreservesOwnerActorTenantCallerAndEarliestExpiry(t *testing.T) {
	a, s, clock, key, c := authorityFixture(t)
	c.Owner.Kind = auth.AuthorityOwnerOrganization
	c.Actor = &auth.AuthorityOwner{Kind: auth.AuthorityOwnerUser, ID: "human", Version: 3}
	c.MembershipID = "membership"
	c.MembershipVersion = 4
	c.Parents = []auth.AuthorityGrant{{ID: "parent", Version: 2, ExpiresAt: time.Unix(c.ExpiresAt+1, 0)}}
	for _, dimension := range []auth.ValidityDimension{
		{Kind: auth.ValidityParentGrant, ID: "parent", Version: 2}, {Kind: auth.ValidityActor, ID: "human", Version: 3}, {Kind: auth.ValidityMembership, ID: "membership", Version: 4},
	} {
		s.validity.Dimensions = append(s.validity.Dimensions, auth.DimensionValidity{Dimension: dimension, Active: true, VerifiedAt: clock.Now(), ValidUntil: clock.Now().Add(15 * time.Second)})
	}
	resignValidity(t, s, key)
	p, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, c))
	if err != nil {
		t.Fatal(err)
	}
	b := p.Bindings()
	if b.Owner.Kind != auth.AuthorityOwnerOrganization || b.Actor.ID != "human" || b.Tenant != "tenant" || b.ClientID != "workload" {
		t.Fatal("authority identities collapsed")
	}
	if !p.ValidUntil().Equal(clock.Now().Add(14 * time.Second)) {
		t.Fatal("earliest source expiry lost")
	}
	b.Actor.ID = "changed"
	b.Scopes[0] = "changed"
	b.Parents[0].ID = "changed"
	if p.Bindings().Actor.ID != "human" || p.Bindings().Scopes[0] != "read" || p.Bindings().Parents[0].ID != "parent" {
		t.Fatal("mutable projection altered principal")
	}
	if err := p.Validate(clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(time.Time{}); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("zero clock accepted")
	}
	if err := p.Validate(time.Unix(c.IssuedAt-1, 0)); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("future principal accepted")
	}
	if err := (auth.ResourcePrincipal{}).Validate(clock.Now()); !errors.Is(err, auth.ErrInvalidProof) {
		t.Fatal("zero principal accepted")
	}
}

func TestSignedValidityCannotBeForgedMismatchedOrRenewed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*auth.SignedValidityEvidence)
		resign bool
	}{
		{"issuer", func(e *auth.SignedValidityEvidence) { e.Issuer = "other" }, true}, {"environment", func(e *auth.SignedValidityEvidence) { e.Environment = "other" }, true},
		{"token", func(e *auth.SignedValidityEvidence) { e.TokenID = "abcdefghijklmnopqrstuw" }, true}, {"tenant", func(e *auth.SignedValidityEvidence) { e.Tenant = "other" }, true},
		{"signature", func(e *auth.SignedValidityEvidence) { e.Signature[0] ^= 1 }, false}, {"missing-signature", func(e *auth.SignedValidityEvidence) { e.Signature = nil }, false},
		{"unknown-key", func(e *auth.SignedValidityEvidence) { e.KeyID = "unknown" }, true}, {"missing-dimension", func(e *auth.SignedValidityEvidence) { e.Dimensions = e.Dimensions[1:] }, true},
		{"dimension-id", func(e *auth.SignedValidityEvidence) { e.Dimensions[0].Dimension.ID = "other" }, true}, {"dimension-version", func(e *auth.SignedValidityEvidence) { e.Dimensions[0].Dimension.Version = 2 }, true},
		{"revoked-root", func(e *auth.SignedValidityEvidence) { e.Dimensions[0].Active = false }, true}, {"future-source", func(e *auth.SignedValidityEvidence) {
			e.Dimensions[0].VerifiedAt = e.Dimensions[0].VerifiedAt.Add(2 * time.Second)
		}, true},
		{"unbounded-age", func(e *auth.SignedValidityEvidence) {
			e.Dimensions[0].ValidUntil = e.Dimensions[0].ValidUntil.Add(time.Nanosecond)
		}, false},
		{"duplicate-dimension", func(e *auth.SignedValidityEvidence) { e.Dimensions[1] = e.Dimensions[0] }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, _, key, c := authorityFixture(t)
			tc.mutate(&s.validity)
			if tc.resign {
				resignValidity(t, s, key)
			}
			if _, err := a.ValidateAccessToken(context.Background(), signedAccess(t, key, c)); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestEveryAuthorityDimensionRevocationFailsClosedWithoutEvents(t *testing.T) {
	for _, kind := range []auth.ValidityDimensionKind{auth.ValidityRootCredential, auth.ValidityRootGrant, auth.ValidityParentGrant, auth.ValidityOwner, auth.ValidityActor, auth.ValidityTenant, auth.ValidityMembership, auth.ValidityClient, auth.ValiditySigning} {
		t.Run(string(kind), func(t *testing.T) {
			a, source, clock, key, claims := authorityFixture(t)
			claims.Actor = &auth.AuthorityOwner{Kind: auth.AuthorityOwnerUser, ID: "human", Version: 3}
			claims.MembershipID, claims.MembershipVersion = "membership", 4
			claims.Parents = []auth.AuthorityGrant{{ID: "parent", Version: 2, ExpiresAt: time.Unix(claims.ExpiresAt+1, 0)}}
			for _, dimension := range []auth.ValidityDimension{{Kind: auth.ValidityParentGrant, ID: "parent", Version: 2}, {Kind: auth.ValidityActor, ID: "human", Version: 3}, {Kind: auth.ValidityMembership, ID: "membership", Version: 4}} {
				source.validity.Dimensions = append(source.validity.Dimensions, auth.DimensionValidity{Dimension: dimension, Active: true, VerifiedAt: clock.Now(), ValidUntil: clock.Now().Add(20 * time.Second)})
			}
			resignValidity(t, source, key)
			token := signedAccess(t, key, claims)
			cached, err := a.ValidateAccessToken(context.Background(), token)
			if err != nil {
				t.Fatal(err)
			}
			for i := range source.validity.Dimensions {
				if source.validity.Dimensions[i].Dimension.Kind == kind {
					source.validity.Dimensions[i].Active = false
				}
			}
			resignValidity(t, source, key)
			if _, err := a.ValidateAccessToken(context.Background(), token); err == nil {
				t.Fatal("revoked dimension accepted")
			}
			// Even if the event never arrives, a copied warm principal cannot keep
			// authority beyond its immutable original evidence deadline.
			copy := cached
			clock.advance(30 * time.Second)
			if err := copy.Validate(clock.Now()); !errors.Is(err, auth.ErrExpiredProof) {
				t.Fatal("lost event renewed cached authority")
			}
		})
	}
}

func TestAuthorityAuthenticateAndMalformedTokensFailClosed(t *testing.T) {
	a, _, _, key, c := authorityFixture(t)
	token := signedAccess(t, key, c)
	for _, credential := range []auth.Credential{auth.NewBearerCredential(token), func() auth.Credential { v := auth.NewBearerCredential(token); return &v }()} {
		result, err := a.Authenticate(context.Background(), credential)
		p, ok := result.Principal()
		if err != nil || !ok || p.Subject() != c.Subject || p.Issuer() != c.Issuer {
			t.Fatal("trusted authentication lost principal")
		}
	}
	var nilBearer *auth.BearerCredential
	for _, credential := range []auth.Credential{nil, nilBearer, auth.NewBasicCredential("user", "pass"), auth.NewBearerCredential("invalid")} {
		if _, err := a.Authenticate(context.Background(), credential); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	for _, token := range []string{"", strings.Repeat("a", 16385), "a.b", "a.b.c.d", "!.a.a", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"key"}`)) + ".a.a", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"at+jwt","kid":"unknown"}`)) + ".a.a"} {
		if _, err := a.ValidateAccessToken(context.Background(), token); err == nil {
			t.Fatal("malformed token accepted")
		}
	}
	parts := strings.Split(token, ".")
	parts[2] = "!"
	if _, err := a.ValidateAccessToken(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("invalid signature encoding accepted")
	}
	parts = strings.Split(token, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, err := a.ValidateAccessToken(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("invalid signature accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ValidateAccessToken(ctx, token); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("canceled validation accepted")
	}
	var absentContext context.Context
	if _, err := a.ValidateAccessToken(absentContext, token); !errors.Is(err, auth.ErrAuthenticationUnavailable) {
		t.Fatal("nil context accepted")
	}
	if _, err := ((*auth.AuthorityAuthenticator)(nil)).ValidateAccessToken(context.Background(), token); !errors.Is(err, auth.ErrInvalidConfiguration) {
		t.Fatal("nil authority accepted")
	}
	for _, body := range []string{"", "\xff", `true true`, `{"iss":"one","iss":"two"}`, `{"unknown":true}`, `{"iss":`, `{123:1}`, `{"key":1`, `[` + strings.Repeat(`0,`, 256) + `0]`, strings.Repeat("[", 10) + strings.Repeat("]", 10)} {
		prefix := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
		bad := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
		if _, err := a.ValidateAccessToken(context.Background(), bad); err == nil {
			t.Fatal("hostile payload accepted")
		}
	}
	prefix := parts[0] + ".!"
	bad := prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
	if _, err := a.ValidateAccessToken(context.Background(), bad); err == nil {
		t.Fatal("signed invalid payload encoding accepted")
	}
}

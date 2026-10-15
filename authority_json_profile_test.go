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

func signedRawAccess(key ed25519.PrivateKey, header, payload string) string {
	prefix := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(prefix)))
}

func TestSignedAccessJSONRequiresExactClosedFieldNames(t *testing.T) {
	authority, source, clock, key, claims := authorityFixture(t)
	claims.Actor = &auth.AuthorityOwner{Kind: auth.AuthorityOwnerUser, ID: "human", Version: 1}
	claims.MembershipID, claims.MembershipVersion = "membership", 1
	claims.Parents = []auth.AuthorityGrant{{ID: "parent", Version: 1, ExpiresAt: time.Unix(claims.ExpiresAt+1, 0)}}
	for _, dimension := range []auth.ValidityDimension{
		{Kind: auth.ValidityActor, ID: "human", Version: 1},
		{Kind: auth.ValidityMembership, ID: "membership", Version: 1},
		{Kind: auth.ValidityParentGrant, ID: "parent", Version: 1},
	} {
		source.validity.Dimensions = append(source.validity.Dimensions, auth.DimensionValidity{Dimension: dimension, Active: true, VerifiedAt: clock.Now(), ValidUntil: clock.Now().Add(20 * time.Second)})
	}
	resignValidity(t, source, key)
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := string(encoded)
	const header = `{"alg":"EdDSA","typ":"at+jwt","kid":"key"}`
	control, err := authority.ValidateAccessToken(context.Background(), signedRawAccess(key, header, payload))
	if err != nil || control.Bindings().Actor.ID != "human" || len(control.Bindings().Parents) != 1 {
		t.Fatal("canonical signed control with fresh exact authority evidence failed")
	}
	for _, malformed := range []string{
		`{"alg":"none","ALG":"EdDSA","typ":"at+jwt","kid":"key"}`,
		`{"ALG":"EdDSA","TYP":"at+jwt","KID":"key"}`,
		`{"alg":"EdDSA","typ":"at+jwt","\u212Aid":"key"}`,
		`{"alg":"EdDSA","alg":"EdDSA","typ":"at+jwt","kid":"key"}`,
		`{"alg":"EdDSA","typ":"at+jwt","kid":"key","unknown":true}`,
	} {
		principal, err := authority.ValidateAccessToken(context.Background(), signedRawAccess(key, malformed, payload))
		if !errors.Is(err, auth.ErrCredentialsInvalid) || !principal.ValidUntil().IsZero() {
			t.Error("signed noncanonical header accepted or misclassified")
		}
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"top-level-alias", `"iss":`, `"ISS":`},
		{"top-level-conflict", `"iss":`, `"iss":"other","ISS":`},
		{"unicode-fold-alias", `"sub":`, `"\u017Fub":`},
		{"top-level-duplicate", `"iss":`, `"iss":"other","iss":`},
		{"top-level-unknown", `"iss":`, `"unknown":true,"iss":`},
		{"owner-alias", `"owner":{"kind":`, `"owner":{"KIND":`},
		{"owner-conflict", `"owner":{"kind":`, `"owner":{"kind":"organization","KIND":`},
		{"owner-unknown", `"owner":{"kind":`, `"owner":{"unknown":true,"kind":`},
		{"owner-duplicate", `"owner":{"kind":`, `"owner":{"kind":"organization","kind":`},
		{"actor-alias", `"actor":{"kind":`, `"actor":{"KIND":`},
		{"actor-conflict", `"actor":{"kind":`, `"actor":{"kind":"organization","KIND":`},
		{"credential-alias", `"root_credential":{"id":`, `"root_credential":{"ID":`},
		{"credential-conflict", `"root_credential":{"id":`, `"root_credential":{"id":"other","ID":`},
		{"grant-alias", `"root_grant":{"id":`, `"root_grant":{"ID":`},
		{"grant-conflict", `"root_grant":{"id":`, `"root_grant":{"id":"other","ID":`},
		{"parent-alias", `"parents":[{"id":`, `"parents":[{"ID":`},
		{"parent-conflict", `"parents":[{"id":`, `"parents":[{"id":"other","ID":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(payload, tc.old) != 1 {
				t.Fatal("mutation did not select exactly one canonical field")
			}
			malformed := strings.Replace(payload, tc.old, tc.replacement, 1)
			principal, err := authority.ValidateAccessToken(context.Background(), signedRawAccess(key, header, malformed))
			if !errors.Is(err, auth.ErrCredentialsInvalid) || !principal.ValidUntil().IsZero() || !errors.Is(principal.Validate(clock.Now()), auth.ErrInvalidProof) {
				t.Fatal("signed noncanonical claims accepted or misclassified")
			}
		})
	}
}

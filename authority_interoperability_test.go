package authentication_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestIndependentOpenSSLSharedIssuerFixtures(t *testing.T) {
	bytes, err := os.ReadFile("testdata/shared-issuer/openssl-eddsa.json")
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile("testdata/shared-issuer/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		FixtureSHA string `json:"fixture_sha256"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes)
	if hex.EncodeToString(digest[:]) != manifest.FixtureSHA {
		t.Fatal("independent fixture digest drifted")
	}
	var fixture struct {
		PublicKey string                      `json:"public_key"`
		Tokens    map[string]string           `json:"tokens"`
		Validity  auth.SignedValidityEvidence `json:"validity"`
	}
	if err := json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(fixture.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	source := &authoritySource{validity: fixture.Validity}
	clock := &authorityClock{now: time.Date(2026, 10, 1, 12, 0, 1, 0, time.UTC)}
	a, err := auth.NewAuthorityAuthenticator(auth.AuthorityConfig{Issuer: "https://issuer.example", Environment: "test", Audience: "resource", Algorithm: "EdDSA", Profile: "shared-issuer-v1", AccessKeys: []auth.AuthorityKey{{ID: "key", PublicKey: ed25519.PublicKey(key)}}, EvidenceKeys: []auth.AuthorityKey{{ID: "key", PublicKey: ed25519.PublicKey(key)}}, Source: source, Clock: clock, ReadTimeout: time.Second, ClockUncertainty: time.Second, MaximumDelegationDepth: 4, RequiredScopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range fixture.Tokens {
		t.Run(name, func(t *testing.T) {
			p, err := a.ValidateAccessToken(context.Background(), token)
			if name != "valid" {
				if err == nil {
					t.Fatal("independently signed denial case accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c := p.Bindings()
			if c.Owner.Kind != auth.AuthorityOwnerOrganization || c.Owner.ID != "organization" || c.Actor.ID != "human" || c.Tenant != "tenant" || c.ClientID != "workload" || c.RootGrant.ID != "root" || len(c.Parents) != 1 || c.Parents[0].ID != "parent" {
				t.Fatal("independent lineage/identity bindings changed")
			}
		})
	}
}

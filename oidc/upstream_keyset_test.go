package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	upstreamoidc "github.com/coreos/go-oidc/v3/oidc"
	authentication "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authentication/authtest"
	authoidc "github.com/faustbrian/go-authentication/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

func TestCallerRemoteKeySetPreservesSupportedKeysAndFailsClosed(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(jose.JSONWebKey{Key: &private.PublicKey, KeyID: "signing", Algorithm: "RS256", Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}
	unsupported := `{"kty":"OKP","crv":"Ed448","x":"AA"},{"kty":"OKP","crv":"X448","x":"AA"}`
	mixed := string(public) + "," + unsupported
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name           string
		keys           string
		wrongSignature bool
		accept         bool
	}{
		{name: "supported only", keys: string(public), accept: true},
		{name: "supported with unsupported peers", keys: mixed, accept: true},
		{name: "unsupported only", keys: unsupported},
		{name: "malformed supported peer", keys: string(public) + `,{"kty":"RSA","n":"!","e":"AQAB"}`},
		{name: "wrong signature with mixed keys", keys: mixed, wrongSignature: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: callerJWKSBytes(`{"keys":[` + test.keys + `]}`)}
			ctx := upstreamoidc.ClientContext(context.Background(), client)
			keySet := upstreamoidc.NewRemoteKeySet(ctx, "https://issuer.example.test/keys")
			nonceCalls := 0
			validator, err := authoidc.NewWithKeySet(authoidc.Config{
				Issuer: "https://issuer.example.test", ClientID: "client-1",
				Algorithms: []string{"RS256"}, Clock: authtest.NewClock(now),
				NonceValidator: authoidc.NonceValidatorFunc(func(_ context.Context, nonce string) error {
					nonceCalls++
					if nonce != "nonce-1" {
						return errors.New("unexpected nonce")
					}
					return nil
				}),
			}, keySet)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(map[string]any{
				"sub": "user-1", "iss": "https://issuer.example.test", "aud": "client-1",
				"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "nonce-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			key := private
			if test.wrongSignature {
				key = wrongPrivate
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "signing"))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			result, err := validator.Authenticate(context.Background(), authentication.NewBearerCredential(token))
			principal, authenticated := result.Principal()
			if test.accept {
				if err != nil || !authenticated || principal.Subject() != "user-1" ||
					principal.Method() != "oidc" || principal.Issuer() != "https://issuer.example.test" || nonceCalls != 1 {
					t.Fatalf("expected authenticated principal and one nonce call: err=%v authenticated=%v nonceCalls=%d", err, authenticated, nonceCalls)
				}
			} else if !errors.Is(err, authentication.ErrCredentialsRejected) || authenticated || principal.Subject() != "" || nonceCalls != 0 {
				t.Fatalf("expected rejection without principal or nonce use: err=%v authenticated=%v nonceCalls=%d", err, authenticated, nonceCalls)
			}
		})
	}
}

// The caller owns its HTTP client; no live provider is needed for this boundary.
type callerJWKSBytes string

func (body callerJWKSBytes) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(body))), Request: request,
	}, nil
}

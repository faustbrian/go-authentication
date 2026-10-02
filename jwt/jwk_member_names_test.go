package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authentication/authtest"
	authjwt "github.com/faustbrian/go-authentication/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestStaticJWKMemberNamesCannotInjectUsage(t *testing.T) {
	for _, family := range []string{"oct", "RSA", "EC", "OKP"} {
		t.Run(family, func(t *testing.T) {
			verification, signer, algorithm, method := memberNameSigningMaterial(t, family)
			for _, name := range []string{`x":0,"use`, "quote\"\\\nname"} {
				t.Run(name, func(t *testing.T) {
					key, err := jwk.Import(verification)
					if err != nil {
						t.Fatalf("Import() error = %v", err)
					}
					for field, value := range map[string]any{
						jwk.KeyIDKey: "signing", jwk.AlgorithmKey: algorithm, name: "enc",
					} {
						if err := key.Set(field, value); err != nil {
							t.Fatalf("Set() error = %v", err)
						}
					}
					if _, present := key.KeyUsage(); present {
						t.Fatal("fixture unexpectedly has a registered use member")
					}
					set := jwk.NewSet()
					if err := set.AddKey(key); err != nil {
						t.Fatalf("AddKey() error = %v", err)
					}
					validator, err := authjwt.New(memberNameConfiguration(algorithm, set, nil))
					if err != nil {
						t.Fatalf("New() rejected a literal extension member: %v", err)
					}
					assertMemberNameAuthentication(t, validator, signer, algorithm, method)
				})
			}
		})
	}
}

func TestRemoteJWKMemberNamesSurviveDefensiveCopies(t *testing.T) {
	verification, signer, algorithm, method := memberNameSigningMaterial(t, "RSA")
	public, ok := verification.(*rsa.PublicKey)
	if !ok {
		t.Fatal("RSA fixture is not a public key")
	}
	const extension = `x":0,"use`
	// encoding/json is the independent oracle: do not use the serializer
	// being tested to construct the incoming remote JWK document.
	body, err := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "signing", "alg": "RS256", extension: "sig",
		"n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	client := &http.Client{Transport: memberNameTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Request: request,
			Header: http.Header{
				"Content-Type":  {"application/jwk-set+json"},
				"Cache-Control": {"max-age=3600"},
			},
			Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body)),
		}, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	remote, err := authjwt.NewRemote(ctx, "https://keys.example.test/jwks", authjwt.WithHTTPClient(client))
	if err != nil {
		t.Fatalf("NewRemote() error = %v", err)
	}
	t.Cleanup(func() {
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := remote.Shutdown(shutdown); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
	})
	for snapshot := range 2 {
		set, err := remote.KeySet(ctx)
		if err != nil {
			t.Fatalf("KeySet() error = %v", err)
		}
		if set.Len() != 1 {
			t.Fatalf("KeySet() length = %d, want 1", set.Len())
		}
		key, present := set.Key(0)
		if !present {
			t.Fatal("KeySet() is missing the key")
		}
		var value string
		if err := key.Get(extension, &value); err != nil || value != "sig" {
			t.Fatal("KeySet() lost the literal extension member")
		}
		if _, present := key.KeyUsage(); present {
			t.Fatal("KeySet() injected a registered use member")
		}
		if kid, present := key.KeyID(); !present || kid != "signing" {
			t.Fatal("KeySet() changed the key identity")
		}
		if snapshot == 0 {
			if err := key.Set(jwk.KeyIDKey, "mutated-snapshot"); err != nil {
				t.Fatalf("Set(kid) error = %v", err)
			}
		}
	}
	validator, err := authjwt.New(memberNameConfiguration(algorithm, nil, remote))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	assertMemberNameAuthentication(t, validator, signer, algorithm, method)
}

func memberNameSigningMaterial(t *testing.T, family string) (any, any, jwa.SignatureAlgorithm, golangjwt.SigningMethod) {
	t.Helper()
	switch family {
	case "oct":
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("random secret error = %v", err)
		}
		return secret, secret, jwa.HS256(), golangjwt.SigningMethodHS256
	case "RSA":
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("RSA key generation error = %v", err)
		}
		return &private.PublicKey, private, jwa.RS256(), golangjwt.SigningMethodRS256
	case "EC":
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("EC key generation error = %v", err)
		}
		return &private.PublicKey, private, jwa.ES256(), golangjwt.SigningMethodES256
	case "OKP":
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("OKP key generation error = %v", err)
		}
		return public, private, jwa.EdDSAEd25519(), golangjwt.SigningMethodEdDSA
	default:
		t.Fatalf("unsupported test family %q", family)
		return nil, nil, jwa.HS256(), golangjwt.SigningMethodHS256
	}
}

func memberNameConfiguration(algorithm jwa.SignatureAlgorithm, keys jwk.Set, provider authjwt.KeyProvider) authjwt.Config {
	return authjwt.Config{
		Issuer: "https://issuer.example.test", Audience: "orders",
		Algorithms: []jwa.SignatureAlgorithm{algorithm}, KeySet: keys, Provider: provider,
		Clock: authtest.NewClock(time.Unix(1_800_000_000, 0)),
	}
}

func assertMemberNameAuthentication(t *testing.T, validator *authjwt.Validator, signer any, algorithm jwa.SignatureAlgorithm, method golangjwt.SigningMethod) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	token := golangjwt.NewWithClaims(method, golangjwt.MapClaims{
		"sub": "member", "iss": "https://issuer.example.test", "aud": "orders",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "signing"
	// golang-jwt calls its Ed25519 signer EdDSA; this module deliberately
	// accepts only the non-deprecated Ed25519 JOSE algorithm identifier.
	token.Header["alg"] = algorithm.String()
	signed, err := token.SignedString(signer)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	result, err := validator.Authenticate(context.Background(), authentication.NewBearerCredential(signed))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	principal, present := result.Principal()
	if !present || principal.Subject() != "member" || principal.Method() != "jwt" {
		t.Fatal("Authenticate() did not return the expected JWT principal")
	}
}

type memberNameTransport func(*http.Request) (*http.Response, error)

func (transport memberNameTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

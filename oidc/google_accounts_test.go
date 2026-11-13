package oidc_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	upstreamoidc "github.com/coreos/go-oidc/v3/oidc"
	authoidc "github.com/faustbrian/go-authentication/oidc/v2"
	authentication "github.com/faustbrian/go-authentication/v3"
	"github.com/faustbrian/go-authentication/v3/authtest"
	jose "github.com/go-jose/go-jose/v4"
)

const canonicalGoogleIssuer = "https://accounts.google.com"
const legacyGoogleIssuer = "accounts.google.com"

func TestGoogleAccountsWithKeySetProjectsCanonicalIdentity(t *testing.T) {
	private := rsaKey(t)
	keys := &googleRecordingKeySet{delegate: &upstreamoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&private.PublicKey}}}
	validator, err := authoidc.NewGoogleAccountsWithKeySet(googleConfig(), keys)
	if err != nil {
		t.Fatal("construct explicit Google validator", err)
	}
	for _, issuer := range []string{canonicalGoogleIssuer, legacyGoogleIssuer} {
		claims := googleClaims(issuer)
		claims["auth_time"] = oidcNow.Add(-time.Minute).Unix()
		claims["at_hash"], claims["c_hash"] = oidcHash("access-for-binding"), oidcHash("code-for-binding")
		token := signIDToken(t, private, claims)
		principal, err := validator.ValidateIDToken(context.Background(), token, authoidc.TokenBinding{AccessToken: "access-for-binding", AuthorizationCode: "code-for-binding"})
		if err != nil || principal.Issuer() != canonicalGoogleIssuer || principal.Subject() != "google-subject" {
			t.Fatal("explicit Google issuer forms did not produce one admitted identity", err)
		}
		if keys.lastToken() != token {
			t.Fatal("signature verifier did not receive the original compact token")
		}
		if !principal.AuthenticatedAt().Equal(oidcNow.Add(-time.Minute)) {
			t.Fatal("Google issuer projection replaced original authentication time")
		}
		if _, retained := principal.Claims()["iss"]; retained {
			t.Fatal("registered source issuer leaked into application claims")
		}
	}
}

func TestGoogleAccountsDiscoveryProjectsCanonicalIdentity(t *testing.T) {
	metadata, err := os.ReadFile("testdata/google-openid-configuration-2026-08-09.json")
	if err != nil {
		t.Fatal(err)
	}
	private := rsaKey(t)
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: "google-snapshot", Algorithm: "RS256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	config := googleConfig()
	// Only network IO is doubled. The existing bounded discovery/JWKS parser,
	// remote key owner and real signature/claim admission all remain exercised.
	config.HTTPClient = &http.Client{Transport: externalRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.URL.String())
		body := metadata
		switch request.URL.String() {
		case "https://accounts.google.com/.well-known/openid-configuration":
		case "https://www.googleapis.com/oauth2/v3/certs":
			body = keys
		default:
			t.Fatal("discovery or keys escaped the exact configured HTTPS origins")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	})}
	validator, err := authoidc.NewGoogleAccounts(context.Background(), config)
	if err != nil {
		t.Fatal("construct bounded discovery-backed Google validator", err)
	}
	for _, issuer := range []string{canonicalGoogleIssuer, legacyGoogleIssuer} {
		token := signIDTokenWithKeyID(t, private, "google-snapshot", googleClaims(issuer))
		principal, err := validator.ValidateBearer(context.Background(), token)
		if err != nil || principal.Issuer() != canonicalGoogleIssuer || principal.Subject() != "google-subject" {
			t.Fatal("discovered Google key did not validate both issuer forms", err)
		}
	}
	if len(requests) != 2 {
		t.Fatal("known fresh Google keys did not remain in the existing bounded cache")
	}
}

func TestGoogleAccountsRejectsNoncanonicalConfigurationBeforeDiscovery(t *testing.T) {
	private := rsaKey(t)
	keys := &upstreamoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&private.PublicKey}}
	for _, issuer := range []string{"", legacyGoogleIssuer, "http://accounts.google.com", canonicalGoogleIssuer + "/", canonicalGoogleIssuer + ":443", canonicalGoogleIssuer + "/tenant", "https://ACCOUNTS.google.com", "https://attacker.example", canonicalGoogleIssuer + "?issuer=other"} {
		config := googleConfig()
		config.Issuer = issuer
		requests := 0
		config.HTTPClient = &http.Client{Transport: externalRoundTripperFunc(func(*http.Request) (*http.Response, error) {
			requests++
			return nil, errors.New("unexpected discovery")
		})}
		if validator, err := authoidc.NewGoogleAccounts(context.Background(), config); validator != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) || requests != 0 {
			t.Fatal("noncanonical Google configuration reached discovery or returned a validator")
		}
		if validator, err := authoidc.NewGoogleAccountsWithKeySet(config, keys); validator != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
			t.Fatal("noncanonical Google key-set configuration was admitted")
		}
	}
	if validator, err := authoidc.NewGoogleAccountsWithKeySet(googleConfig(), nil); validator != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatal("Google profile bypassed existing key-set admission")
	}
}

func TestGoogleAccountsPreservesSignedProofChecks(t *testing.T) {
	private, wrongPrivate := rsaKey(t), rsaKey(t)
	keys := &upstreamoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&private.PublicKey}}
	config := googleConfig()
	config.TrustedAudiences = []string{"extra-client"}
	validator, err := authoidc.NewGoogleAccountsWithKeySet(config, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{canonicalGoogleIssuer, legacyGoogleIssuer} {
		for _, test := range []struct {
			name  string
			alter func(map[string]any)
		}{
			{"wrong issuer", func(c map[string]any) { c["iss"] = "https://attacker.example" }},
			{"issuer trailing slash", func(c map[string]any) { c["iss"] = canonicalGoogleIssuer + "/" }},
			{"issuer port alias", func(c map[string]any) { c["iss"] = "https://accounts.google.com:443" }},
			{"wrong audience", func(c map[string]any) { c["aud"] = "unknown-client" }},
			{"wrong authorized party", func(c map[string]any) { c["azp"] = "extra-client" }},
			{"multiple audiences without azp", func(c map[string]any) { c["aud"] = []string{"client-1", "extra-client"} }},
			{"wrong nonce", func(c map[string]any) { c["nonce"] = "other-nonce" }},
			{"absent nonce", func(c map[string]any) { delete(c, "nonce") }},
			{"expired", func(c map[string]any) { c["exp"] = oidcNow.Add(-2 * time.Minute).Unix() }},
			{"future issued at", func(c map[string]any) { c["iat"] = oidcNow.Add(2 * time.Minute).Unix() }},
			{"not yet valid", func(c map[string]any) { c["nbf"] = oidcNow.Add(2 * time.Minute).Unix() }},
			{"missing subject", func(c map[string]any) { delete(c, "sub") }},
			{"wrong access hash", func(c map[string]any) { c["at_hash"] = oidcHash("different-access") }},
			{"wrong code hash", func(c map[string]any) { c["c_hash"] = oidcHash("different-code") }},
		} {
			t.Run(issuer+"/"+test.name, func(t *testing.T) {
				claims := googleClaims(issuer)
				claims["at_hash"], claims["c_hash"] = oidcHash("access-for-binding"), oidcHash("code-for-binding")
				test.alter(claims)
				principal, err := validator.ValidateIDToken(context.Background(), signIDToken(t, private, claims), authoidc.TokenBinding{AccessToken: "access-for-binding", AuthorizationCode: "code-for-binding"})
				if !errors.Is(err, authentication.ErrCredentialsRejected) || principal.Subject() != "" || principal.Issuer() != "" {
					t.Fatal("Google compatibility admitted an invalid signed proof or disclosed identity", err)
				}
			})
		}
		principal, err := validator.ValidateBearer(context.Background(), signIDToken(t, wrongPrivate, googleClaims(issuer)))
		if !errors.Is(err, authentication.ErrCredentialsRejected) || principal.Subject() != "" {
			t.Fatal("Google compatibility bypassed real signature verification")
		}
	}
}

func TestGoogleAccountsRetainsDefaultStrictModeAndCallerCancellation(t *testing.T) {
	private := rsaKey(t)
	keys := &upstreamoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&private.PublicKey}}
	strict, err := authoidc.NewWithKeySet(googleConfig(), keys)
	if err != nil {
		t.Fatal(err)
	}
	token := signIDToken(t, private, googleClaims(legacyGoogleIssuer))
	if principal, err := strict.ValidateBearer(context.Background(), token); !errors.Is(err, authentication.ErrCredentialsRejected) || principal.Subject() != "" {
		t.Fatal("unselected constructor inherited Google compatibility")
	}
	selected, err := authoidc.NewGoogleAccountsWithKeySet(googleConfig(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if principal, err := strict.ValidateBearer(context.Background(), token); !errors.Is(err, authentication.ErrCredentialsRejected) || principal.Subject() != "" {
		t.Fatal("selecting another validator changed an existing strict instance")
	}
	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		principal, err := selected.ValidateBearer(ctx, token)
		cancel()
		if !errors.Is(err, authentication.ErrAuthenticationUnavailable) || principal.Subject() != "" || ctx.Err() == nil {
			t.Fatal("Google profile renewed canceled or expired caller authority")
		}
		if validator, err := authoidc.NewGoogleAccounts(ctx, googleConfig()); validator != nil || !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
			t.Fatal("Google discovery ignored caller cancellation or deadline")
		}
	}
	var calls sync.WaitGroup
	for range 8 {
		calls.Go(func() {
			principal, err := selected.ValidateBearer(context.Background(), token)
			if err != nil || principal.Issuer() != canonicalGoogleIssuer {
				t.Error("concurrent immutable Google validation failed")
			}
		})
	}
	calls.Wait()
}

func TestGoogleAccountsDiscoveryKeepsMetadataAndBodyBoundsStrict(t *testing.T) {
	metadata, err := os.ReadFile("testdata/google-openid-configuration-2026-08-09.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"legacy metadata issuer", "oversized keys"} {
		t.Run(kind, func(t *testing.T) {
			config := googleConfig()
			config.MaxHTTPBodyBytes = 4096
			keyRequests := 0
			config.HTTPClient = &http.Client{Transport: externalRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
				body := metadata
				if request.URL.Host == "accounts.google.com" && kind == "legacy metadata issuer" {
					body = bytes.Replace(metadata, []byte(`"issuer": "https://accounts.google.com"`), []byte(`"issuer": "accounts.google.com"`), 1)
				} else if request.URL.Host == "www.googleapis.com" {
					keyRequests++
					body = []byte(strings.Repeat(" ", 4097))
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
			})}
			validator, err := authoidc.NewGoogleAccounts(context.Background(), config)
			if validator != nil || err == nil {
				t.Fatal("Google profile relaxed discovery issuer or key response bounds")
			}
			if kind == "legacy metadata issuer" && (!errors.Is(err, authentication.ErrInvalidConfiguration) || keyRequests != 0) {
				t.Fatal("token issuer compatibility leaked into metadata/key acquisition")
			}
		})
	}
}

func FuzzGoogleAccountsIssuerPolicy(f *testing.F) {
	for _, issuer := range []string{canonicalGoogleIssuer, legacyGoogleIssuer, canonicalGoogleIssuer + "/", "http://accounts.google.com", "https://accounts.google.com:443", "https://attacker.example", "", "accounts.google.com\x00"} {
		f.Add(issuer, true)
		f.Add(issuer, false)
	}
	f.Fuzz(func(t *testing.T, issuer string, selected bool) {
		if len(issuer) > 4096 {
			return
		}
		private := rsaKey(t)
		keys := &upstreamoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&private.PublicKey}}
		var validator *authoidc.Validator
		var err error
		if selected {
			validator, err = authoidc.NewGoogleAccountsWithKeySet(googleConfig(), keys)
		} else {
			validator, err = authoidc.NewWithKeySet(googleConfig(), keys)
		}
		if err != nil {
			t.Fatal(err)
		}
		principal, err := validator.ValidateBearer(context.Background(), signIDToken(t, private, googleClaims(issuer)))
		accepted := issuer == canonicalGoogleIssuer || selected && issuer == legacyGoogleIssuer
		if accepted {
			if err != nil || principal.Issuer() != canonicalGoogleIssuer || principal.Subject() != "google-subject" {
				t.Fatal("Google policy lost an exact supported issuer or stable identity")
			}
		} else if err == nil || principal.Subject() != "" || principal.Issuer() != "" {
			t.Fatal("Google policy admitted another issuer or disclosed rejected identity")
		}
	})
}

func googleConfig() authoidc.Config {
	return authoidc.Config{Issuer: canonicalGoogleIssuer, ClientID: "client-1", Algorithms: []string{"RS256"}, Clock: authtest.NewClock(oidcNow), ClockSkew: time.Minute, DiscoveryTimeout: time.Second, NonceValidator: authoidc.NonceValidatorFunc(func(_ context.Context, nonce string) error {
		if nonce != "nonce-1" {
			return errors.New("nonce refused")
		}
		return nil
	})}
}

func googleClaims(issuer string) map[string]any {
	return map[string]any{"iss": issuer, "sub": "google-subject", "aud": "client-1", "iat": oidcNow.Unix(), "exp": oidcNow.Add(time.Hour).Unix(), "nonce": "nonce-1"}
}

type googleRecordingKeySet struct {
	mu       sync.Mutex
	delegate upstreamoidc.KeySet
	last     string
}

func (s *googleRecordingKeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	s.mu.Lock()
	s.last = token
	s.mu.Unlock()
	return s.delegate.VerifySignature(ctx, token)
}

func (s *googleRecordingKeySet) lastToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

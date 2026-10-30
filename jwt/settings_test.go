package jwt_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	authjwt "github.com/faustbrian/go-authentication/jwt/v2"
	authentication "github.com/faustbrian/go-authentication/v3"
)

func validRemoteSettings() authjwt.RemoteSettings {
	return authjwt.RemoteSettings{
		Issuer:                "https://identity.example",
		Audience:              "service",
		JWKURL:                "https://identity.example/.well-known/jwks.json?tenant=a",
		Algorithms:            []string{"RS256", "ES256"},
		Skew:                  30 * time.Second,
		MaxTokenBytes:         16 << 10,
		MaxJWKBodyBytes:       1 << 20,
		InitializationTimeout: 5 * time.Second,
		MinRefresh:            time.Minute,
		MaxRefresh:            time.Hour,
	}
}

func TestRemoteSettingsAcceptInclusiveBounds(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(*authjwt.RemoteSettings){
		"defaults":           func(*authjwt.RemoteSettings) {},
		"zero skew":          func(value *authjwt.RemoteSettings) { value.Skew = 0 },
		"maximum skew":       func(value *authjwt.RemoteSettings) { value.Skew = 5 * time.Minute },
		"one token byte":     func(value *authjwt.RemoteSettings) { value.MaxTokenBytes = 1 },
		"maximum token":      func(value *authjwt.RemoteSettings) { value.MaxTokenBytes = 64 << 10 },
		"one JWK byte":       func(value *authjwt.RemoteSettings) { value.MaxJWKBodyBytes = 1 },
		"maximum JWK":        func(value *authjwt.RemoteSettings) { value.MaxJWKBodyBytes = 8 << 20 },
		"maximum fetch":      func(value *authjwt.RemoteSettings) { value.InitializationTimeout = 30 * time.Second },
		"equal refresh":      func(value *authjwt.RemoteSettings) { value.MaxRefresh = value.MinRefresh },
		"maximum refresh":    func(value *authjwt.RemoteSettings) { value.MaxRefresh = 24 * time.Hour },
		"URL without path":   func(value *authjwt.RemoteSettings) { value.JWKURL = "https://identity.example" },
		"opaque audience":    func(value *authjwt.RemoteSettings) { value.Audience = "urn:service" },
		"single algorithm":   func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"Ed25519"} },
		"secure but allowed": func(value *authjwt.RemoteSettings) { value.AllowInsecureHTTP = false },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := validRemoteSettings()
			change(&settings)
			if err := settings.Validate(authjwt.SettingsPolicy{}); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestRemoteSettingsRejectIncompleteOrUnboundedTrust(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(*authjwt.RemoteSettings){
		"missing issuer":       func(value *authjwt.RemoteSettings) { value.Issuer = "" },
		"padded issuer":        func(value *authjwt.RemoteSettings) { value.Issuer = " https://identity.example" },
		"missing audience":     func(value *authjwt.RemoteSettings) { value.Audience = "" },
		"padded audience":      func(value *authjwt.RemoteSettings) { value.Audience = " audience " },
		"plain HTTP JWK URL":   func(value *authjwt.RemoteSettings) { value.JWKURL = "http://identity.test/jwks" },
		"other scheme":         func(value *authjwt.RemoteSettings) { value.JWKURL = "ftp://identity.test/jwks" },
		"relative URL":         func(value *authjwt.RemoteSettings) { value.JWKURL = "/jwks" },
		"empty host":           func(value *authjwt.RemoteSettings) { value.JWKURL = "https:///jwks" },
		"URL user":             func(value *authjwt.RemoteSettings) { value.JWKURL = "https://user@identity.test/jwks" },
		"URL fragment":         func(value *authjwt.RemoteSettings) { value.JWKURL += "#keys" },
		"malformed URL":        func(value *authjwt.RemoteSettings) { value.JWKURL = "%" },
		"no algorithms":        func(value *authjwt.RemoteSettings) { value.Algorithms = nil },
		"negative skew":        func(value *authjwt.RemoteSettings) { value.Skew = -time.Second },
		"large skew":           func(value *authjwt.RemoteSettings) { value.Skew = 5*time.Minute + 1 },
		"zero token bytes":     func(value *authjwt.RemoteSettings) { value.MaxTokenBytes = 0 },
		"large token":          func(value *authjwt.RemoteSettings) { value.MaxTokenBytes = 64<<10 + 1 },
		"zero JWK bytes":       func(value *authjwt.RemoteSettings) { value.MaxJWKBodyBytes = 0 },
		"large JWK":            func(value *authjwt.RemoteSettings) { value.MaxJWKBodyBytes = 8<<20 + 1 },
		"zero fetch timeout":   func(value *authjwt.RemoteSettings) { value.InitializationTimeout = 0 },
		"long fetch timeout":   func(value *authjwt.RemoteSettings) { value.InitializationTimeout = 30*time.Second + 1 },
		"zero min refresh":     func(value *authjwt.RemoteSettings) { value.MinRefresh = 0 },
		"refresh order":        func(value *authjwt.RemoteSettings) { value.MaxRefresh = value.MinRefresh - time.Second },
		"long refresh":         func(value *authjwt.RemoteSettings) { value.MaxRefresh = 24*time.Hour + 1 },
		"unknown algorithm":    func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"unknown"} },
		"lowercase algorithm":  func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"rs256"} },
		"none algorithm":       func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"none"} },
		"deprecated algorithm": func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"Ed25519", "EdDSA"} },
		"duplicate algorithm":  func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"RS256", "RS256"} },
		"symmetric algorithm":  func(value *authjwt.RemoteSettings) { value.Algorithms = []string{"RS256", "HS256"} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := validRemoteSettings()
			change(&settings)
			err := settings.Validate(authjwt.SettingsPolicy{PermitInsecure: true})
			if !errors.Is(err, authentication.ErrInvalidConfiguration) {
				t.Fatalf("Validate() error = %v, want invalid configuration", err)
			}
			if strings.Contains(err.Error(), "identity.example") || strings.Contains(err.Error(), "user@") {
				t.Fatalf("Validate() error disclosed configured values: %v", err)
			}
		})
	}
}

func TestRemoteSettingsInsecureModeRequiresDeploymentPermission(t *testing.T) {
	t.Parallel()

	insecure := validRemoteSettings()
	insecure.AllowInsecureHTTP = true
	insecure.JWKURL = "http://127.0.0.1:8080/jwks"
	insecure.Algorithms = []string{"HS256", "RS256"}
	if err := insecure.Validate(authjwt.SettingsPolicy{PermitInsecure: true}); err != nil {
		t.Fatalf("permitted insecure settings error = %v", err)
	}
	if err := insecure.Validate(authjwt.SettingsPolicy{}); !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("unpermitted insecure settings error = %v, want invalid configuration", err)
	}

	secureURL := validRemoteSettings()
	secureURL.AllowInsecureHTTP = true
	if err := secureURL.Validate(authjwt.SettingsPolicy{}); !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("insecure flag without permission error = %v, want invalid configuration", err)
	}
}

func TestRemoteSettingsValidateDoesNotRetainOrMutateAlgorithms(t *testing.T) {
	t.Parallel()

	settings := validRemoteSettings()
	algorithms := settings.Algorithms
	if err := settings.Validate(authjwt.SettingsPolicy{}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if strings.Join(algorithms, ",") != "RS256,ES256" {
		t.Fatalf("Validate() changed caller algorithms to %v", algorithms)
	}
}

func FuzzRemoteSettingsValidate(f *testing.F) {
	for _, seed := range []struct {
		url       string
		algorithm string
		insecure  bool
	}{
		{"https://identity.example/jwks", "RS256", false},
		{"http://127.0.0.1/jwks", "HS256", true},
		{"https://user@identity.example/jwks#keys", "none", false},
		{"%", "EdDSA", true},
	} {
		f.Add(seed.url, seed.algorithm, seed.insecure)
	}
	f.Fuzz(func(t *testing.T, jwkURL, algorithm string, insecure bool) {
		settings := validRemoteSettings()
		settings.JWKURL, settings.Algorithms, settings.AllowInsecureHTTP = jwkURL, []string{algorithm}, insecure
		if err := settings.Validate(authjwt.SettingsPolicy{}); err == nil && insecure {
			t.Fatal("insecure settings accepted without deployment permission")
		}
		err := settings.Validate(authjwt.SettingsPolicy{PermitInsecure: true})
		if err != nil {
			field := strings.TrimPrefix(err.Error(), authentication.ErrInvalidConfiguration.Error()+": JWT remote settings ")
			if !errors.Is(err, authentication.ErrInvalidConfiguration) || (field != "JWKURL" && field != "Algorithms") {
				t.Fatalf("Validate() error = %v", err)
			}
			return
		}
		parsed, parseErr := url.Parse(jwkURL)
		if parseErr != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && (!insecure || parsed.Scheme != "http")) ||
			algorithm == "none" || (!insecure && strings.HasPrefix(algorithm, "HS")) {
			t.Fatalf("Validate() accepted URL %q with algorithm %q", jwkURL, algorithm)
		}
	})
}

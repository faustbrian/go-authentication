package jwt

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// Deployment ceilings for RemoteSettings. They bound operator configuration
// before NewRemote and New allocate caches or accept tokens; the constructors
// accept any positive bound and keep their own structural checks.
const (
	maxSettingsSkew                 = 5 * time.Minute
	maxSettingsTokenBytes           = 64 << 10
	maxSettingsJWKBodyBytes   int64 = 8 << 20
	maxSettingsInitialization       = 30 * time.Second
	maxSettingsRefresh              = 24 * time.Hour
)

// RemoteSettings is operator configuration for an issuer- and audience-bound
// validator backed by a remote JWK set. Its zero value is invalid. Callers keep
// their own configuration tags and copy values in; Validate does not retain or
// modify the Algorithms slice.
type RemoteSettings struct {
	// Issuer and Audience must be non-empty without surrounding whitespace.
	Issuer   string
	Audience string
	// JWKURL is an absolute https URL with a host and no user information or
	// fragment. A query is permitted. Plain http requires AllowInsecureHTTP.
	JWKURL string
	// Algorithms are registered JWS names, case-sensitive, without duplicates,
	// "none" or deprecated names. Symmetric HS* names require AllowInsecureHTTP.
	Algorithms []string
	// Skew is between zero and five minutes inclusive.
	Skew time.Duration
	// MaxTokenBytes is between one byte and 64 KiB inclusive.
	MaxTokenBytes int
	// MaxJWKBodyBytes is between one byte and 8 MiB inclusive.
	MaxJWKBodyBytes int64
	// InitializationTimeout is positive and at most 30 seconds.
	InitializationTimeout time.Duration
	// MinRefresh is positive; MaxRefresh is at least MinRefresh and at most 24 hours.
	MinRefresh time.Duration
	MaxRefresh time.Duration
	// AllowInsecureHTTP permits a plain-http JWK URL and symmetric algorithms.
	// It is accepted only when SettingsPolicy.PermitInsecure is true.
	AllowInsecureHTTP bool
}

// SettingsPolicy carries deployment facts that RemoteSettings cannot know. Its
// zero value is the production policy.
type SettingsPolicy struct {
	// PermitInsecure reports that the deployment is local or test-only, so
	// RemoteSettings.AllowInsecureHTTP may be honored.
	PermitInsecure bool
}

// Validate reports the first invalid field as ErrInvalidConfiguration. Errors
// name the field, never its configured value.
func (s RemoteSettings) Validate(policy SettingsPolicy) error {
	if s.AllowInsecureHTTP && !policy.PermitInsecure {
		return invalidSettings("AllowInsecureHTTP")
	}
	if invalidSettingsIdentity(s.Issuer) {
		return invalidSettings("Issuer")
	}
	if invalidSettingsIdentity(s.Audience) {
		return invalidSettings("Audience")
	}
	parsed, err := url.Parse(s.JWKURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && (!s.AllowInsecureHTTP || parsed.Scheme != "http")) {
		return invalidSettings("JWKURL")
	}
	if s.Skew < 0 || s.Skew > maxSettingsSkew {
		return invalidSettings("Skew")
	}
	if s.MaxTokenBytes <= 0 || s.MaxTokenBytes > maxSettingsTokenBytes {
		return invalidSettings("MaxTokenBytes")
	}
	if s.MaxJWKBodyBytes <= 0 || s.MaxJWKBodyBytes > maxSettingsJWKBodyBytes {
		return invalidSettings("MaxJWKBodyBytes")
	}
	if s.InitializationTimeout <= 0 || s.InitializationTimeout > maxSettingsInitialization {
		return invalidSettings("InitializationTimeout")
	}
	if s.MinRefresh <= 0 || s.MaxRefresh < s.MinRefresh || s.MaxRefresh > maxSettingsRefresh {
		return invalidSettings("refresh bounds")
	}
	return validateSettingsAlgorithms(s.Algorithms, s.AllowInsecureHTTP)
}

func validateSettingsAlgorithms(names []string, allowSymmetric bool) error {
	if len(names) == 0 {
		return invalidSettings("Algorithms")
	}
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		algorithm, ok := jwa.LookupSignatureAlgorithm(name)
		if !ok || algorithm == jwa.NoSignature() || algorithm.IsDeprecated() ||
			(algorithm.IsSymmetric() && !allowSymmetric) {
			return invalidSettings("Algorithms")
		}
		if _, duplicate := seen[name]; duplicate {
			return invalidSettings("Algorithms")
		}
		seen[name] = struct{}{}
	}
	return nil
}

func invalidSettingsIdentity(value string) bool {
	return value == "" || strings.TrimSpace(value) != value
}

func invalidSettings(field string) error {
	return fmt.Errorf("%w: JWT remote settings %s", authentication.ErrInvalidConfiguration, field)
}

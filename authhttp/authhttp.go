// Package authhttp preserves the original HTTP authentication adapter import
// path. New code should import github.com/faustbrian/go-authentication/adapters/http.
//
// Deprecated: use github.com/faustbrian/go-authentication/adapters/http.
package authhttp

import (
	"net/http"

	authentication "github.com/faustbrian/go-authentication"
	authenticationhttp "github.com/faustbrian/go-authentication/adapters/http"
)

// Source is an explicitly enabled HTTP credential location.
//
// Deprecated: use authenticationhttp.Source.
type Source = authenticationhttp.Source

// Extractor rejects ambiguous credentials across all enabled sources.
//
// Deprecated: use authenticationhttp.Extractor.
type Extractor = authenticationhttp.Extractor

// BearerOption configures a bearer source.
//
// Deprecated: use authenticationhttp.BearerOption.
type BearerOption = authenticationhttp.BearerOption

// APIKeyOption configures an API-key source.
//
// Deprecated: use authenticationhttp.APIKeyOption.
type APIKeyOption = authenticationhttp.APIKeyOption

// CredentialExtractor extracts one typed credential from an HTTP request.
//
// Deprecated: use authenticationhttp.CredentialExtractor.
type CredentialExtractor = authenticationhttp.CredentialExtractor

// MiddlewareOption configures HTTP authentication middleware.
//
// Deprecated: use authenticationhttp.MiddlewareOption.
type MiddlewareOption = authenticationhttp.MiddlewareOption

// FormatChallenge serializes a challenge for a WWW-Authenticate field value.
//
// Deprecated: use authenticationhttp.FormatChallenge.
func FormatChallenge(challenge authentication.Challenge) (string, error) {
	return authenticationhttp.FormatChallenge(challenge)
}

// NewExtractor creates an extractor from one or more explicit sources.
//
// Deprecated: use authenticationhttp.NewExtractor.
func NewExtractor(sources ...Source) (*Extractor, error) {
	return authenticationhttp.NewExtractor(sources...)
}

// BasicAuthorization enables Basic extraction from the Authorization header.
//
// Deprecated: use authenticationhttp.BasicAuthorization.
func BasicAuthorization() Source { return authenticationhttp.BasicAuthorization() }

// WithBearerMaxBytes sets the inclusive bearer-token size bound.
//
// Deprecated: use authenticationhttp.WithBearerMaxBytes.
func WithBearerMaxBytes(maximum int) BearerOption {
	return authenticationhttp.WithBearerMaxBytes(maximum)
}

// WithBearerPipe permits the pipe character in an opaque bearer credential.
//
// Deprecated: use authenticationhttp.WithBearerPipe.
func WithBearerPipe() BearerOption { return authenticationhttp.WithBearerPipe() }

// BearerAuthorization enables bearer extraction from the Authorization header.
//
// Deprecated: use authenticationhttp.BearerAuthorization.
func BearerAuthorization(options ...BearerOption) Source {
	return authenticationhttp.BearerAuthorization(options...)
}

// BearerQuery explicitly enables bearer extraction from a query parameter.
//
// Deprecated: credentials in URLs can be retained by logs, proxies, and
// browser history. Prefer authenticationhttp.BearerAuthorization for new designs.
func BearerQuery(name string, options ...BearerOption) Source {
	return authenticationhttp.BearerQuery(name, options...)
}

// BearerCookie explicitly enables bearer extraction from a cookie.
//
// Deprecated: use authenticationhttp.BearerCookie.
func BearerCookie(name string, options ...BearerOption) Source {
	return authenticationhttp.BearerCookie(name, options...)
}

// WithAPIKeyMaxBytes sets the inclusive API-key size bound.
//
// Deprecated: use authenticationhttp.WithAPIKeyMaxBytes.
func WithAPIKeyMaxBytes(maximum int) APIKeyOption {
	return authenticationhttp.WithAPIKeyMaxBytes(maximum)
}

// APIKeyHeader explicitly enables API-key extraction from two headers.
//
// Deprecated: use authenticationhttp.APIKeyHeader.
func APIKeyHeader(idHeader, keyHeader string, options ...APIKeyOption) Source {
	return authenticationhttp.APIKeyHeader(idHeader, keyHeader, options...)
}

// APIKeyQuery explicitly enables API-key extraction from two query parameters.
//
// Deprecated: credentials in URLs can be retained by logs, proxies, and
// browser history. Prefer authenticationhttp.APIKeyHeader for new designs.
func APIKeyQuery(idParameter, keyParameter string, options ...APIKeyOption) Source {
	return authenticationhttp.APIKeyQuery(idParameter, keyParameter, options...)
}

// APIKeyCookie explicitly enables API-key extraction from two cookies.
//
// Deprecated: use authenticationhttp.APIKeyCookie.
func APIKeyCookie(idCookie, keyCookie string, options ...APIKeyOption) Source {
	return authenticationhttp.APIKeyCookie(idCookie, keyCookie, options...)
}

// WithOptionalAnonymous permits anonymous access only when credentials are absent.
//
// Deprecated: use authenticationhttp.WithOptionalAnonymous.
func WithOptionalAnonymous() MiddlewareOption {
	return authenticationhttp.WithOptionalAnonymous()
}

// WithChallenges configures fallback challenges for authentication failures.
//
// Deprecated: use authenticationhttp.WithChallenges.
func WithChallenges(challenges ...authentication.Challenge) MiddlewareOption {
	return authenticationhttp.WithChallenges(challenges...)
}

// NewMiddleware creates fail-closed authentication-only net/http middleware.
//
// Deprecated: use authenticationhttp.NewMiddleware.
func NewMiddleware(extractor CredentialExtractor, authenticator authentication.Authenticator, options ...MiddlewareOption) (func(http.Handler) http.Handler, error) {
	return authenticationhttp.NewMiddleware(extractor, authenticator, options...)
}

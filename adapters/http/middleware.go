package authenticationhttp

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"

	authentication "github.com/faustbrian/go-authentication/v3"
)

// CredentialExtractor extracts one typed credential from an HTTP request.
type CredentialExtractor interface {
	// Extract must refuse malformed/ambiguous input and identify absent credentials
	// with ErrCredentialsAbsent. Borrow request/body without mutation or hidden IO;
	// providers reused across requests must support concurrency. The middleware
	// does not contain collaborator panics or preempt their blocking work.
	Extract(*http.Request) (authentication.Credential, error)
}

type middlewareConfig struct {
	optional   bool
	challenges []string
	failure    FailureWriter
}

// FailureWriter renders a refused request. The middleware has already chosen
// status, 401 or 503, and added the WWW-Authenticate challenges a 401 carries;
// the writer must write exactly that status and its own body. err is the
// extraction or authentication failure and may wrap a provider cause, so a
// writer must not echo it. Writer panics propagate.
type FailureWriter func(writer http.ResponseWriter, request *http.Request, status int, err error)

// WithFailureWriter replaces the default fixed text/plain failure body, for
// example with a JSON document. Status selection and challenges are unchanged.
// A nil writer is invalid configuration.
func WithFailureWriter(failure FailureWriter) MiddlewareOption {
	return func(configuration *middlewareConfig) error {
		if failure == nil {
			return fmt.Errorf("%w: HTTP failure writer", authentication.ErrInvalidConfiguration)
		}
		configuration.failure = failure
		return nil
	}
}

// MiddlewareOption configures HTTP authentication middleware.
type MiddlewareOption func(*middlewareConfig) error

// WithOptionalAnonymous permits anonymous access only when credentials are absent.
func WithOptionalAnonymous() MiddlewareOption {
	return func(configuration *middlewareConfig) error {
		configuration.optional = true
		return nil
	}
}

// WithChallenges configures fallback challenges for authentication failures.
func WithChallenges(challenges ...authentication.Challenge) MiddlewareOption {
	return func(configuration *middlewareConfig) error {
		for _, challenge := range challenges {
			formatted, err := FormatChallenge(challenge)
			if err != nil {
				return fmt.Errorf("%w: HTTP challenge", authentication.ErrInvalidConfiguration)
			}
			configuration.challenges = append(configuration.challenges, formatted)
		}
		return nil
	}
}

// NewMiddleware validates nonnil/typed-nil collaborators and creates
// authentication-only middleware. Optional anonymous access applies only to
// extraction absence; other failures never authorize access. A 401 requires a
// valid failure/fallback challenge; otherwise refusal is a fixed-text 503. It
// shallow-copies request context, borrowing body/headers and next handler.
// Provider/handler/writer panics propagate, no additional cancellation barrier
// is imposed, and caller owns concurrency, request limits and lifetimes.
func NewMiddleware(extractor CredentialExtractor, authenticator authentication.Authenticator, options ...MiddlewareOption) (func(http.Handler) http.Handler, error) {
	if isNilInterface(extractor) || isNilInterface(authenticator) {
		return nil, fmt.Errorf("%w: HTTP middleware dependency", authentication.ErrInvalidConfiguration)
	}
	configuration := middlewareConfig{}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			credential, err := extractor.Extract(request)
			if err != nil {
				if configuration.optional && errors.Is(err, authentication.ErrCredentialsAbsent) {
					ctx := authentication.ContextWithPrincipal(request.Context(), authentication.AnonymousPrincipal())
					next.ServeHTTP(writer, request.WithContext(ctx))
					return
				}
				writeFailure(writer, request, err, configuration)
				return
			}

			result, err := authenticator.Authenticate(request.Context(), credential)
			if err != nil {
				writeFailure(writer, request, err, configuration)
				return
			}
			principal, ok := result.Principal()
			if !ok {
				writeFailure(writer, request, authentication.NewFailure(authentication.FailureUnavailable,
					authentication.WithFailureCause(authentication.ErrInvalidConfiguration)), configuration)
				return
			}

			ctx := authentication.ContextWithPrincipal(request.Context(), principal)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}, nil
}

func writeFailure(writer http.ResponseWriter, request *http.Request, err error, configuration middlewareConfig) {
	status := http.StatusUnauthorized
	message := "authentication failed"
	if errors.Is(err, authentication.ErrAuthenticationUnavailable) || !classifiedHTTPFailure(err) {
		status = http.StatusServiceUnavailable
		message = "authentication unavailable"
	}

	if status == http.StatusUnauthorized {
		challenges := failureChallenges(err)
		if len(challenges) == 0 {
			challenges = configuration.challenges
		}
		if len(challenges) == 0 {
			status = http.StatusServiceUnavailable
			message = "authentication unavailable"
		} else {
			for _, challenge := range challenges {
				writer.Header().Add("WWW-Authenticate", challenge)
			}
		}
	}
	if configuration.failure != nil {
		configuration.failure(writer, request, status, err)
		return
	}
	http.Error(writer, message, status)
}

func failureChallenges(err error) []string {
	var failure *authentication.Failure
	if !errors.As(err, &failure) {
		return nil
	}
	var formatted []string
	for _, challenge := range failure.Challenges() {
		value, formatErr := FormatChallenge(challenge)
		if formatErr == nil {
			formatted = append(formatted, value)
		}
	}
	return formatted
}

func classifiedHTTPFailure(err error) bool {
	return errors.Is(err, authentication.ErrCredentialsAbsent) ||
		errors.Is(err, authentication.ErrCredentialsInvalid) ||
		errors.Is(err, authentication.ErrCredentialsRejected) ||
		errors.Is(err, authentication.ErrAmbiguousCredentials) ||
		errors.Is(err, authentication.ErrAuthenticationUnavailable)
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

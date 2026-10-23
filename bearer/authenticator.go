// Package bearer provides New for borrowed opaque-token validators and
// NewStatic for atomically replaceable digest/principal snapshots. It does not
// decode JWTs, enforce transport grammar, authorize actions or own providers/IO
// shutdown. Static scans all digest candidates, not a whole-call timing guarantee.
package bearer

import (
	"context"
	"errors"
	"fmt"

	authentication "github.com/faustbrian/go-authentication/v3"
)

const defaultMaxTokenBytes = 8 * 1024

// Validator validates an opaque bearer token and returns an immutable principal.
type Validator interface {
	// ValidateBearer borrows a nonnil context and plaintext credentials. Return a concrete
	// principal with Method bearer on success; classify policy failures explicitly
	// and bound/cooperate with IO. Provider state/lifetime and concurrent safety
	// remain caller-owned; direct function adapters do not recover panics.
	ValidateBearer(context.Context, string) (authentication.Principal, error)
}

// ValidatorFunc adapts a function to Validator.
type ValidatorFunc func(context.Context, string) (authentication.Principal, error)

// ValidateBearer directly invokes the borrowed function. Nil functions/provider
// panics propagate; no deadline, preemption, redaction or retry is added.
func (f ValidatorFunc) ValidateBearer(ctx context.Context, token string) (authentication.Principal, error) {
	return f(ctx, token)
}

type config struct{ maxTokenBytes int }

// Option configures an Authenticator.
type Option func(*config)

// WithMaxTokenBytes sets the inclusive token-size bound.
func WithMaxTokenBytes(maximum int) Option {
	return func(configuration *config) { configuration.maxTokenBytes = maximum }
}

// Authenticator validates opaque bearer credentials through a callback or interface.
type Authenticator struct {
	validator     Validator
	maxTokenBytes int
}

// New requires a nonnil provider and positive configured byte bounds, defaulting
// to 8 KiB tokens. Unlike Static, positive callback bounds have no
// default-sized ceiling. Typed-nil providers are not detected; provider state
// remains borrowed and callbacks/options are not panic-contained.
func New(validator Validator, options ...Option) (*Authenticator, error) {
	configuration := config{maxTokenBytes: defaultMaxTokenBytes}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}
	if validator == nil || configuration.maxTokenBytes <= 0 {
		return nil, fmt.Errorf("%w: bearer validator", authentication.ErrInvalidConfiguration)
	}

	return &Authenticator{validator: validator, maxTokenBytes: configuration.maxTokenBytes}, nil
}

// Authenticate checks initial cancellation and concrete credential type/size
// before a synchronous provider call. Typed Failure errors pass through; other
// errors become unavailable with an inspectable raw cause. Anonymous or wrong-
// method principals fail unavailable. There is no post-callback cancellation
// check, retry, panic recovery or deep copy of provider state.
func (a *Authenticator) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureUnavailable,
			authentication.WithFailureCause(err))
	}
	bearerCredential, ok := credential.(authentication.BearerCredential)
	if !ok || bearerCredential.Token() == "" || len(bearerCredential.Token()) > a.maxTokenBytes {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureInvalid)
	}

	principal, err := a.validator.ValidateBearer(ctx, bearerCredential.Token())
	if err != nil {
		var failure *authentication.Failure
		if errors.As(err, &failure) {
			return authentication.Result{}, err
		}
		return authentication.Result{}, authentication.NewFailure(authentication.FailureUnavailable,
			authentication.WithFailureCause(err))
	}
	if principal.IsAnonymous() || principal.Method() != "bearer" {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureUnavailable,
			authentication.WithFailureCause(authentication.ErrInvalidPrincipal))
	}

	return authentication.NewAuthenticatedResult(principal)
}

var _ authentication.Authenticator = (*Authenticator)(nil)

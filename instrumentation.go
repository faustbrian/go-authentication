package authentication

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	clockpkg "github.com/faustbrian/go-clock"
)

// Outcome is the bounded authentication outcome reported to instrumentation.
type Outcome string

const (
	// OutcomeAuthenticated marks completion with an authenticated Result.
	OutcomeAuthenticated Outcome = "authenticated"
	// OutcomeAnonymous marks completion with explicit anonymous state.
	OutcomeAnonymous Outcome = "anonymous"
	// OutcomeFailed marks completion with an error.
	OutcomeFailed Outcome = "failed"
)

// Event carries category/duration telemetry, never credential fields. Its
// string types can still contain application data; concrete owned adapters
// project unknown categories to fixed labels, not arbitrary custom providers.
type Event struct {
	// Outcome is the attempt state; custom strings must be screened by instrumenters.
	Outcome Outcome
	// Failure is a Failure kind when available; empty means no typed failure classification.
	Failure FailureKind
	// Duration is measured elapsed time; the decorator clamps negative clock movement to zero.
	Duration time.Duration
}

// BeginInstrumenter begins instrumentation for one authentication attempt.
// Implementations must not derive attributes from credential contents.
type BeginInstrumenter interface {
	// Begin runs synchronously and may return a replacement context plus completion
	// callback. Providers must preserve cancellation policy, bound latency and
	// screen custom categories. Reuse requires concurrent safety. The decorator
	// contains telemetry panics, not blocking; it invokes a returned callback once
	// only when the wrapped authentication call returns normally.
	Begin(context.Context, CredentialKind) (context.Context, func(Event))
}

// Instrumented decorates an authenticator with failure-isolated telemetry.
type Instrumented struct {
	authenticator Authenticator
	instrumenter  BeginInstrumenter
	clock         clockpkg.Clock
}

// NewInstrumentedWithBegin creates an authentication instrumentation decorator
// using the preferred one-attempt observation vocabulary. Nil and typed-nil
// dependencies are refused; provider/clock state remains borrowed. No goroutine,
// flush or provider shutdown is owned; concurrent reuse requires collaborators
// to support it.
func NewInstrumentedWithBegin(authenticator Authenticator, instrumenter BeginInstrumenter, clock clockpkg.Clock) (*Instrumented, error) {
	if isNil(authenticator) || isNil(instrumenter) || isNil(clock) {
		return nil, fmt.Errorf("%w: incomplete instrumentation", ErrInvalidConfiguration)
	}

	return &Instrumented{authenticator: authenticator, instrumenter: instrumenter, clock: clock}, nil
}

// Authenticate reports bounded outcome metadata without changing the wrapped
// authenticator's result or error. Clock/begin/finish panics are isolated, but
// the authenticator's panic propagates and does not run finish. A provider can
// replace the forwarded context; nil replacement keeps the original. No
// callback deadline/preemption or universal custom-category redaction is added.
func (i *Instrumented) Authenticate(ctx context.Context, credential Credential) (Result, error) {
	started := safeNow(i.clock, time.Time{})
	next, finish := safeBegin(i.instrumenter, ctx, safeCredentialKind(credential))
	result, err := i.authenticator.Authenticate(next, credential)

	event := Event{Duration: safeDuration(started, safeNow(i.clock, started))}
	if err != nil {
		event.Outcome = OutcomeFailed
		var failure *Failure
		if errors.As(err, &failure) {
			event.Failure = failure.Kind()
		}
	} else if result.State() == ResultAnonymous {
		event.Outcome = OutcomeAnonymous
	} else {
		event.Outcome = OutcomeAuthenticated
	}
	safeFinish(finish, event)

	return result, err
}

func safeBegin(instrumenter BeginInstrumenter, ctx context.Context, kind CredentialKind) (
	next context.Context,
	finish func(Event),
) {
	next = ctx
	defer func() {
		if recover() != nil {
			next = ctx
			finish = nil
		}
	}()

	candidate, callback := instrumenter.Begin(ctx, kind)
	if candidate != nil {
		next = candidate
	}
	return next, callback
}

func safeFinish(finish func(Event), event Event) {
	if finish == nil {
		return
	}
	defer func() { _ = recover() }()
	finish(event)
}

func safeCredentialKind(credential Credential) (kind CredentialKind) {
	if credential == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			kind = ""
		}
	}()
	return credential.Kind()
}

func safeNow(clock clockpkg.Clock, fallback time.Time) (now time.Time) {
	now = fallback
	defer func() { _ = recover() }()
	return clock.Now()
}

func safeDuration(started, finished time.Time) time.Duration {
	return max(finished.Sub(started), 0)
}

func isNil(value any) bool {
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

var _ Authenticator = (*Instrumented)(nil)

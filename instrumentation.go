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
	OutcomeAuthenticated Outcome = "authenticated"
	OutcomeAnonymous     Outcome = "anonymous"
	OutcomeFailed        Outcome = "failed"
)

// Event contains bounded, secret-free authentication telemetry.
type Event struct {
	Outcome  Outcome
	Failure  FailureKind
	Duration time.Duration
}

// BeginInstrumenter begins instrumentation for one authentication attempt.
// Implementations must not derive attributes from credential contents.
type BeginInstrumenter interface {
	Begin(context.Context, CredentialKind) (context.Context, func(Event))
}

// Instrumenter starts instrumentation for one authentication attempt.
// Implementations must not derive attributes from credential contents.
//
// Deprecated: implement BeginInstrumenter and use NewInstrumentedWithBegin in
// new code. Start remains available throughout the v1 compatibility interval.
type Instrumenter interface {
	Start(context.Context, CredentialKind) (context.Context, func(Event))
}

// Clock supplies time to authentication instrumentation.
//
// Deprecated: depend on clock.Clock in new code. This named compatibility
// contract remains available throughout v1.
type Clock interface {
	clockpkg.Clock
}

// Instrumented decorates an authenticator with failure-isolated telemetry.
type Instrumented struct {
	authenticator Authenticator
	instrumenter  BeginInstrumenter
	clock         Clock
}

// NewInstrumented creates an authentication instrumentation decorator for the
// legacy Start-named observation contract.
//
// Deprecated: use NewInstrumentedWithBegin in new code.
func NewInstrumented(authenticator Authenticator, instrumenter Instrumenter, clock Clock) (*Instrumented, error) {
	if isNil(instrumenter) {
		return nil, fmt.Errorf("%w: incomplete instrumentation", ErrInvalidConfiguration)
	}

	return NewInstrumentedWithBegin(authenticator, beginFromStart{instrumenter: instrumenter}, clock)
}

// NewInstrumentedWithBegin creates an authentication instrumentation decorator
// using the preferred one-attempt observation vocabulary.
func NewInstrumentedWithBegin(authenticator Authenticator, instrumenter BeginInstrumenter, clock Clock) (*Instrumented, error) {
	if isNil(authenticator) || isNil(instrumenter) || isNil(clock) {
		return nil, fmt.Errorf("%w: incomplete instrumentation", ErrInvalidConfiguration)
	}

	return &Instrumented{authenticator: authenticator, instrumenter: instrumenter, clock: clock}, nil
}

// Authenticate reports bounded outcome metadata without changing the wrapped
// authenticator's result or error.
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

type beginFromStart struct{ instrumenter Instrumenter }

func (adapter beginFromStart) Begin(ctx context.Context, kind CredentialKind) (context.Context, func(Event)) {
	return adapter.instrumenter.Start(ctx, kind)
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

func safeNow(clock Clock, fallback time.Time) (now time.Time) {
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

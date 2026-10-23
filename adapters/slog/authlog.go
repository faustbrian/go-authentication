// Package authenticationslog adapts authentication Begin instrumentation to
// log/slog using New. It projects categories to constants and omits credentials/
// identity data, but logger/handler/context enrichment and lifetime are caller-
// owned. Recording is synchronous, without provider preemption or goroutines.
package authenticationslog

import (
	"context"
	"fmt"
	"log/slog"

	authentication "github.com/faustbrian/go-authentication/v3"
)

// Instrumenter emits one bounded structured log record per attempt.
type Instrumenter struct {
	logger *slog.Logger
}

// New creates a structured authentication log instrumenter.
func New(logger *slog.Logger) (*Instrumenter, error) {
	if logger == nil {
		return nil, fmt.Errorf("%w: nil logger", authentication.ErrInvalidConfiguration)
	}
	return &Instrumenter{logger: logger}, nil
}

// Begin starts one bounded authentication observation. Categories are projected
// to built-in constants or "unknown"; an empty failure remains empty. Every
// returned callback invocation logs again; unlike the OTel adapter it is not
// one-shot. Provider panics/blocking propagate on direct Begin/finish calls;
// use the core instrumentation decorator for panic isolation, not preemption.
func (i *Instrumenter) Begin(
	ctx context.Context,
	kind authentication.CredentialKind,
) (context.Context, func(authentication.Event)) {
	// Project before creating the callback so it never retains caller-owned
	// category storage, even when its contents match a built-in kind.
	admittedKind := boundedCredentialKind(kind)
	return ctx, func(event authentication.Event) {
		i.logger.InfoContext(ctx, "authentication completed",
			"credential_kind", admittedKind,
			"outcome", boundedOutcome(event.Outcome),
			"failure_kind", boundedFailureKind(event.Failure),
			"duration_ms", event.Duration.Milliseconds(),
		)
	}
}

func boundedCredentialKind(kind authentication.CredentialKind) authentication.CredentialKind {
	switch kind {
	case authentication.CredentialBasic:
		return authentication.CredentialBasic
	case authentication.CredentialBearer:
		return authentication.CredentialBearer
	case authentication.CredentialAPIKey:
		return authentication.CredentialAPIKey
	default:
		return "unknown"
	}
}

func boundedOutcome(outcome authentication.Outcome) authentication.Outcome {
	switch outcome {
	case authentication.OutcomeAuthenticated:
		return authentication.OutcomeAuthenticated
	case authentication.OutcomeAnonymous:
		return authentication.OutcomeAnonymous
	case authentication.OutcomeFailed:
		return authentication.OutcomeFailed
	default:
		return "unknown"
	}
}

func boundedFailureKind(kind authentication.FailureKind) authentication.FailureKind {
	switch kind {
	case "":
		return ""
	case authentication.FailureAbsent:
		return authentication.FailureAbsent
	case authentication.FailureInvalid:
		return authentication.FailureInvalid
	case authentication.FailureRejected:
		return authentication.FailureRejected
	case authentication.FailureUnavailable:
		return authentication.FailureUnavailable
	case authentication.FailureAmbiguous:
		return authentication.FailureAmbiguous
	default:
		return "unknown"
	}
}

var _ authentication.BeginInstrumenter = (*Instrumenter)(nil)

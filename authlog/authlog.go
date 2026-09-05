// Package authlog adapts authentication instrumentation to log/slog.
package authlog

import (
	"context"
	"fmt"
	"log/slog"

	authentication "github.com/faustbrian/go-authentication"
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

// Begin starts one bounded authentication observation.
func (i *Instrumenter) Begin(
	ctx context.Context,
	kind authentication.CredentialKind,
) (context.Context, func(authentication.Event)) {
	return ctx, func(event authentication.Event) {
		i.logger.InfoContext(ctx, "authentication completed",
			"credential_kind", kind,
			"outcome", event.Outcome,
			"failure_kind", event.Failure,
			"duration_ms", event.Duration.Milliseconds(),
		)
	}
}

// Start implements the legacy authentication.Instrumenter contract.
//
// Deprecated: use Begin. It matches the preferred observation vocabulary.
// Migrate callers by replacing Start with Begin. Start remains supported
// throughout v1; its earliest removal is v2.0.0.
func (i *Instrumenter) Start(
	ctx context.Context,
	kind authentication.CredentialKind,
) (context.Context, func(authentication.Event)) {
	return i.Begin(ctx, kind)
}

var _ authentication.Instrumenter = (*Instrumenter)(nil)
var _ authentication.BeginInstrumenter = (*Instrumenter)(nil)

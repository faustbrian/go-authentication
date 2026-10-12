// Package authlog preserves the original structured-log adapter import path.
// New code should import github.com/faustbrian/go-authentication/v2/adapters/slog.
// Instrumenter is a type-identical alias and New forwards; logger/handler
// ownership, synchronous callbacks and privacy projection are canonical behavior.
//
// Deprecated: use github.com/faustbrian/go-authentication/v2/adapters/slog.
package authlog

import (
	"log/slog"

	authenticationslog "github.com/faustbrian/go-authentication/v2/adapters/slog"
)

// Instrumenter emits one bounded structured log record per attempt.
//
// Deprecated: use authenticationslog.Instrumenter.
type Instrumenter = authenticationslog.Instrumenter

// New creates a structured authentication log instrumenter.
//
// Deprecated: use authenticationslog.New.
func New(logger *slog.Logger) (*Instrumenter, error) {
	return authenticationslog.New(logger)
}

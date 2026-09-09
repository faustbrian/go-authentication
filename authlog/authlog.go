// Package authlog preserves the original structured-log adapter import path.
// New code should import github.com/faustbrian/go-authentication/adapters/slog.
//
// Deprecated: use github.com/faustbrian/go-authentication/adapters/slog.
package authlog

import (
	"log/slog"

	authenticationslog "github.com/faustbrian/go-authentication/adapters/slog"
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

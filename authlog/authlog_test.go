package authlog_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authentication/authlog"
)

func TestInstrumenterLogsOnlyBoundedMetadata(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	instrumenter, err := authlog.New(logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.WithValue(context.Background(), contextKey{}, "preserved")
	next, finish := instrumenter.Begin(ctx, authentication.CredentialBearer)
	if next.Value(contextKey{}) != "preserved" {
		t.Fatal("Begin() did not preserve context")
	}
	finish(authentication.Event{
		Outcome:  authentication.OutcomeFailed,
		Failure:  authentication.FailureRejected,
		Duration: 25 * time.Millisecond,
	})

	got := output.String()
	for _, want := range []string{
		`"msg":"authentication completed"`,
		`"credential_kind":"bearer"`,
		`"outcome":"failed"`,
		`"failure_kind":"rejected"`,
		`"duration_ms":25`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log output %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "secret-token") {
		t.Fatalf("log output contains credential: %q", got)
	}
}

func TestLegacyStartDelegatesToBegin(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	instrumenter, err := authlog.New(slog.New(slog.NewJSONHandler(&output, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, finish := instrumenter.Start(context.Background(), authentication.CredentialBasic)
	finish(authentication.Event{Outcome: authentication.OutcomeAuthenticated})
	if !strings.Contains(output.String(), `"credential_kind":"basic"`) {
		t.Fatalf("Start() output = %q", output.String())
	}
}

func TestNewRejectsNilLogger(t *testing.T) {
	t.Parallel()

	if _, err := authlog.New(nil); !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("New(nil) error = %v", err)
	}
}

type contextKey struct{}

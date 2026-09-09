package authlog_test

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"testing"

	authentication "github.com/faustbrian/go-authentication"
	authenticationslog "github.com/faustbrian/go-authentication/adapters/slog"
	legacy "github.com/faustbrian/go-authentication/authlog"
)

func TestLegacyFacadePreservesSlogTypeIdentityAndBehavior(t *testing.T) {
	if reflect.TypeOf((*authenticationslog.Instrumenter)(nil)) != reflect.TypeOf((*legacy.Instrumenter)(nil)) {
		t.Fatal("legacy and successor instrumenters do not have identical reflection identity")
	}

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	legacyInstrumenter, legacyErr := legacy.New(logger)
	successorInstrumenter, successorErr := authenticationslog.New(logger)
	if legacyErr != successorErr || legacyInstrumenter == nil || successorInstrumenter == nil {
		t.Fatalf("legacy=(%v, %v) successor=(%v, %v)", legacyInstrumenter, legacyErr, successorInstrumenter, successorErr)
	}
	ctx := context.Background()
	_, finish := legacyInstrumenter.Begin(ctx, authentication.CredentialBearer)
	finish(authentication.Event{Outcome: authentication.OutcomeAuthenticated})
	if output.Len() == 0 {
		t.Fatal("legacy facade did not retain successor behavior")
	}

	legacyInstrumenter, legacyErr = legacy.New(nil)
	successorInstrumenter, successorErr = authenticationslog.New(nil)
	if legacyInstrumenter != nil || successorInstrumenter != nil || legacyErr == nil || successorErr == nil || legacyErr.Error() != successorErr.Error() {
		t.Fatalf("legacy=(%v, %v) successor=(%v, %v)", legacyInstrumenter, legacyErr, successorInstrumenter, successorErr)
	}
}

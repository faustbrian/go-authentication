package authlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"
	"time"

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

func TestLegacyFacadeCategoricalPrivacy(t *testing.T) {
	for _, method := range []string{"Begin", "Start"} {
		t.Run(method, func(t *testing.T) {
			var output bytes.Buffer
			instrumenter, err := legacy.New(slog.New(slog.NewJSONHandler(&output, nil)))
			if err != nil {
				t.Fatal("constructing legacy instrumenter failed")
			}
			begin := instrumenter.Begin
			if method == "Start" {
				begin = instrumenter.Start
			}
			ctx := context.Background()
			next, finish := begin(ctx, "ordinary-kind")
			if next != ctx {
				t.Fatal("legacy observation changed context")
			}
			finish(authentication.Event{Outcome: "ordinary-outcome", Failure: "ordinary-failure", Duration: 25 * time.Millisecond})
			var record map[string]any
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal("expected one JSON log record")
			}
			if len(record) != 7 || record["msg"] != "authentication completed" || record["duration_ms"] != float64(25) {
				t.Fatal("legacy logging changed the record shape, message or duration")
			}
			for _, key := range []string{"credential_kind", "outcome", "failure_kind"} {
				if record[key] != "unknown" {
					t.Errorf("legacy %s was not the fixed unknown category", key)
				}
			}
		})
	}
}

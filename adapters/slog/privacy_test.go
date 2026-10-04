package authenticationslog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	authlog "github.com/faustbrian/go-authentication/adapters/slog"
)

func TestCategoricalPrivacy(t *testing.T) {
	tests := []struct {
		name    string
		kind    authentication.CredentialKind
		outcome authentication.Outcome
		failure authentication.FailureKind
		want    [3]string
	}{
		{"unfamiliar", "ordinary-kind", "ordinary-outcome", "ordinary-failure", [3]string{"unknown", "unknown", "unknown"}},
		{"empty categories", "", "", "", [3]string{"unknown", "unknown", ""}},
		{"basic", authentication.CredentialBasic, authentication.OutcomeAuthenticated, "", [3]string{"basic", "authenticated", ""}},
		{"bearer", authentication.CredentialBearer, authentication.OutcomeAnonymous, "", [3]string{"bearer", "anonymous", ""}},
		{"api key", authentication.CredentialAPIKey, authentication.OutcomeFailed, authentication.FailureAbsent, [3]string{"api_key", "failed", "absent"}},
		{"invalid", authentication.CredentialBasic, authentication.OutcomeFailed, authentication.FailureInvalid, [3]string{"basic", "failed", "invalid"}},
		{"rejected", authentication.CredentialBearer, authentication.OutcomeFailed, authentication.FailureRejected, [3]string{"bearer", "failed", "rejected"}},
		{"unavailable", authentication.CredentialAPIKey, authentication.OutcomeFailed, authentication.FailureUnavailable, [3]string{"api_key", "failed", "unavailable"}},
		{"ambiguous", authentication.CredentialBasic, authentication.OutcomeFailed, authentication.FailureAmbiguous, [3]string{"basic", "failed", "ambiguous"}},
	}
	for _, method := range []string{"Begin", "Start"} {
		for _, test := range tests {
			t.Run(method+"/"+test.name, func(t *testing.T) {
				var output bytes.Buffer
				instrumenter, err := authlog.New(slog.New(slog.NewJSONHandler(&output, nil)))
				if err != nil {
					t.Fatal("constructing instrumenter failed")
				}
				begin := instrumenter.Begin
				if method == "Start" {
					begin = instrumenter.Start
				}
				ctx := context.WithValue(context.Background(), contextKey{}, "preserved")
				next, finish := begin(ctx, test.kind)
				if next != ctx {
					t.Fatal("observation changed the caller context")
				}
				if output.Len() != 0 {
					t.Fatal("observation logged before completion")
				}
				finish(authentication.Event{Outcome: test.outcome, Failure: test.failure, Duration: 25 * time.Millisecond})
				assertRecord(t, &output, test.want, 25)
			})
		}
	}
}

func TestCategoricalPrivacyPreservesAuthentication(t *testing.T) {
	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{Subject: "ordinary-user", Method: "ordinary"})
	if err != nil {
		t.Fatal("constructing principal failed")
	}
	authenticated, err := authentication.NewAuthenticatedResult(principal)
	if err != nil {
		t.Fatal("constructing result failed")
	}
	failure := authentication.NewFailure("ordinary-failure")
	tests := []struct {
		name    string
		result  authentication.Result
		err     error
		outcome string
		failure string
	}{
		{"authenticated", authenticated, nil, "authenticated", ""},
		{"anonymous", authentication.AnonymousResult(), nil, "anonymous", ""},
		{"failed", authentication.Result{}, failure, "failed", "unknown"},
	}
	for _, constructor := range []string{"Begin", "Start"} {
		for _, test := range tests {
			t.Run(constructor+"/"+test.name, func(t *testing.T) {
				var output bytes.Buffer
				instrumenter, err := authlog.New(slog.New(slog.NewJSONHandler(&output, nil)))
				if err != nil {
					t.Fatal("constructing instrumenter failed")
				}
				ctx := context.WithValue(context.Background(), contextKey{}, "preserved")
				credential := &ordinaryCredential{}
				var calls int
				base := privacyAuthenticatorFunc(func(gotCtx context.Context, gotCredential authentication.Credential) (authentication.Result, error) {
					calls++
					if gotCtx != ctx || gotCredential != credential || gotCredential.Kind() != "ordinary-kind" {
						t.Fatal("logging changed authentication inputs")
					}
					return test.result, test.err
				})
				var wrapped *authentication.Instrumented
				if constructor == "Begin" {
					wrapped, err = authentication.NewInstrumentedWithBegin(base, instrumenter, privacyClock{})
				} else {
					wrapped, err = authentication.NewInstrumented(base, instrumenter, privacyClock{})
				}
				if err != nil {
					t.Fatal("constructing decorated authenticator failed")
				}
				got, gotErr := wrapped.Authenticate(ctx, credential)
				if calls != 1 || !reflect.DeepEqual(got, test.result) || gotErr != test.err {
					t.Fatal("logging changed authentication result or error")
				}
				assertRecord(t, &output, [3]string{"unknown", test.outcome, test.failure}, 0)
			})
		}
	}
}

func assertRecord(t *testing.T, output *bytes.Buffer, want [3]string, milliseconds float64) {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal("expected exactly one JSON log record")
	}
	if len(record) != 7 || record["msg"] != "authentication completed" || record["level"] != "INFO" || record["duration_ms"] != milliseconds {
		t.Fatal("logging changed the record shape, message, level or duration")
	}
	if _, ok := record["time"].(string); !ok {
		t.Fatal("record omitted the handler timestamp")
	}
	for index, key := range []string{"credential_kind", "outcome", "failure_kind"} {
		if record[key] != want[index] {
			t.Errorf("%s did not match the expected bounded category", key)
		}
	}
}

type ordinaryCredential struct{}

func (*ordinaryCredential) Kind() authentication.CredentialKind { return "ordinary-kind" }
func (*ordinaryCredential) String() string                      { return "ordinary credential" }

type privacyAuthenticatorFunc func(context.Context, authentication.Credential) (authentication.Result, error)

func (f privacyAuthenticatorFunc) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
	return f(ctx, credential)
}

type privacyClock struct{}

func (privacyClock) Now() time.Time { return time.Unix(0, 0) }

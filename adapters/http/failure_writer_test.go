package authenticationhttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v3"
	authhttp "github.com/faustbrian/go-authentication/v3/adapters/http"
)

type recordedFailure struct {
	calls   int
	status  int
	err     error
	request *http.Request
}

func (r *recordedFailure) writer() authhttp.FailureWriter {
	return func(writer http.ResponseWriter, request *http.Request, status int, err error) {
		r.calls++
		r.status, r.err, r.request = status, err, request
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(`{"message":"custom"}`))
	}
}

func failingMiddleware(t *testing.T, extract, authenticate error, options ...authhttp.MiddlewareOption) http.Handler {
	t.Helper()
	extractor := extractorFunc(func(*http.Request) (authentication.Credential, error) {
		if extract != nil {
			return nil, extract
		}
		return authentication.NewBearerCredential("secret-token"), nil
	})
	authenticator := middlewareAuthenticatorFunc(func(context.Context, authentication.Credential) (authentication.Result, error) {
		return authentication.Result{}, authenticate
	})
	middleware, err := authhttp.NewMiddleware(extractor, authenticator, options...)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}
	return middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler called after authentication failure")
	}))
}

func TestMiddlewareFailureWriterRendersEveryRefusal(t *testing.T) {
	t.Parallel()

	challenge, err := authentication.NewChallenge("Bearer", map[string]string{"realm": "api"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		extract   error
		auth      error
		options   []authhttp.MiddlewareOption
		status    int
		kind      error
		challenge bool
	}{
		{name: "absent", extract: authentication.NewFailure(authentication.FailureAbsent), options: []authhttp.MiddlewareOption{authhttp.WithChallenges(challenge)}, status: http.StatusUnauthorized, kind: authentication.ErrCredentialsAbsent, challenge: true},
		{name: "rejected", auth: authentication.NewFailure(authentication.FailureRejected), options: []authhttp.MiddlewareOption{authhttp.WithChallenges(challenge)}, status: http.StatusUnauthorized, kind: authentication.ErrCredentialsRejected, challenge: true},
		{name: "unavailable", auth: authentication.NewFailure(authentication.FailureUnavailable), options: []authhttp.MiddlewareOption{authhttp.WithChallenges(challenge)}, status: http.StatusServiceUnavailable, kind: authentication.ErrAuthenticationUnavailable},
		{name: "unclassified", auth: errors.New("store offline"), options: []authhttp.MiddlewareOption{authhttp.WithChallenges(challenge)}, status: http.StatusServiceUnavailable},
		{name: "401 without challenge", auth: authentication.NewFailure(authentication.FailureRejected), status: http.StatusServiceUnavailable, kind: authentication.ErrCredentialsRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorded := &recordedFailure{}
			options := append([]authhttp.MiddlewareOption{authhttp.WithFailureWriter(recorded.writer())}, tt.options...)
			request := httptest.NewRequest(http.MethodGet, "/orders", nil)
			recorder := httptest.NewRecorder()
			failingMiddleware(t, tt.extract, tt.auth, options...).ServeHTTP(recorder, request)

			if recorded.calls != 1 || recorded.status != tt.status || recorded.request != request {
				t.Fatalf("writer calls = %d, status = %d, same request = %v", recorded.calls, recorded.status, recorded.request == request)
			}
			if tt.kind != nil && !errors.Is(recorded.err, tt.kind) {
				t.Fatalf("writer error = %v, want %v", recorded.err, tt.kind)
			}
			if recorder.Code != tt.status || recorder.Body.String() != `{"message":"custom"}` ||
				recorder.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response = %d %q %q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
			}
			values := recorder.Header().Values("WWW-Authenticate")
			if tt.challenge != (len(values) == 1 && values[0] == `Bearer realm="api"`) || (!tt.challenge && len(values) != 0) {
				t.Fatalf("WWW-Authenticate = %#v", values)
			}
		})
	}
}

func TestMiddlewareDefaultFailureBodyIsUnchangedPlainText(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	failingMiddleware(t, nil, authentication.NewFailure(authentication.FailureUnavailable)).
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != "authentication unavailable\n" ||
		!strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("default response = %d %q %q", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	}
}

func TestMiddlewareFailureWriterIsNotCalledOnSuccessOrOptionalAnonymous(t *testing.T) {
	t.Parallel()

	recorded := &recordedFailure{}
	extractor := extractorFunc(func(*http.Request) (authentication.Credential, error) {
		return nil, authentication.NewFailure(authentication.FailureAbsent)
	})
	authenticator := middlewareAuthenticatorFunc(func(context.Context, authentication.Credential) (authentication.Result, error) {
		t.Fatal("authenticator called without a credential")
		return authentication.Result{}, nil
	})
	middleware, err := authhttp.NewMiddleware(extractor, authenticator, authhttp.WithOptionalAnonymous(), authhttp.WithFailureWriter(recorded.writer()))
	if err != nil {
		t.Fatal(err)
	}
	served := false
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !served || recorded.calls != 0 {
		t.Fatalf("served = %v, writer calls = %d", served, recorded.calls)
	}
}

func TestWithFailureWriterRejectsNil(t *testing.T) {
	t.Parallel()

	extractor := extractorFunc(func(*http.Request) (authentication.Credential, error) { return nil, nil })
	authenticator := middlewareAuthenticatorFunc(func(context.Context, authentication.Credential) (authentication.Result, error) {
		return authentication.Result{}, nil
	})
	if _, err := authhttp.NewMiddleware(extractor, authenticator, authhttp.WithFailureWriter(nil)); !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("NewMiddleware(nil writer) error = %v", err)
	}
}

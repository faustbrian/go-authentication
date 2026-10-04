package authentication_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authentication "github.com/faustbrian/go-authentication"
	authenticationhttp "github.com/faustbrian/go-authentication/adapters/http"
	"github.com/faustbrian/go-authentication/apikey"
	legacyhttp "github.com/faustbrian/go-authentication/authhttp"
	"github.com/faustbrian/go-authentication/basic"
	"github.com/faustbrian/go-authentication/bearer"
)

func TestStaticByteAdmissionIsTerminalInComposite(t *testing.T) {
	first, err := basic.NewStaticWithOptions([]basic.Entry{{
		Username: "one", Password: "two", Principal: authentication.PrincipalSpec{Subject: "first"},
	}}, basic.WithMaxUsernameBytes(3), basic.WithMaxPasswordBytes(3))
	if err != nil {
		t.Fatal("constructing first authenticator failed")
	}
	second, err := basic.NewStaticWithOptions([]basic.Entry{{
		Username: "user", Password: "open", Principal: authentication.PrincipalSpec{Subject: "second"},
	}}, basic.WithMaxUsernameBytes(4), basic.WithMaxPasswordBytes(4))
	if err != nil {
		t.Fatal("constructing second authenticator failed")
	}
	composite, err := authentication.NewComposite([]authentication.Binding{
		{Kind: authentication.CredentialBasic, Authenticator: first},
		{Kind: authentication.CredentialBasic, Authenticator: second},
	})
	if err != nil {
		t.Fatal("constructing composite failed")
	}
	credential := authentication.NewBasicCredential("user", "open")
	if result, err := second.Authenticate(context.Background(), credential); err != nil || result.State() != authentication.ResultAuthenticated {
		t.Fatal("credential was not accepted by the later authenticator")
	}
	result, err := composite.Authenticate(context.Background(), credential)
	var failure *authentication.Failure
	if result.State() == authentication.ResultAuthenticated || !errors.As(err, &failure) ||
		failure.Kind() != authentication.FailureInvalid || !errors.Is(err, authentication.ErrCredentialsInvalid) {
		t.Error("over-limit credential fell through to a later authenticator")
	}
}

func TestStaticByteAdmissionPreservesHTTPComposition(t *testing.T) {
	for _, path := range []string{"canonical", "retained"} {
		for _, kind := range []string{"basic", "api_key", "bearer"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
				var authenticator authentication.Authenticator
				var source authenticationhttp.Source
				var err error
				switch kind {
				case "basic":
					authenticator, err = basic.NewStaticWithOptions([]basic.Entry{{
						Username: "user", Password: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
					}}, basic.WithMaxUsernameBytes(4), basic.WithMaxPasswordBytes(4))
					request.SetBasicAuth("user", "open")
					source = authenticationhttp.BasicAuthorization()
					if path == "retained" {
						source = legacyhttp.BasicAuthorization()
					}
				case "api_key":
					authenticator, err = apikey.NewStaticWithOptions([]apikey.Entry{{
						ID: "name", Key: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
					}}, apikey.WithMaxKeyIDBytes(4), apikey.WithMaxKeyBytes(4))
					request.Header.Set("X-Key-ID", "name")
					request.Header.Set("X-Key", "open")
					source = authenticationhttp.APIKeyHeader("X-Key-ID", "X-Key")
					if path == "retained" {
						source = legacyhttp.APIKeyHeader("X-Key-ID", "X-Key")
					}
				case "bearer":
					authenticator, err = bearer.NewStatic([]bearer.Entry{{
						Token: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
					}})
					request.Header.Set("Authorization", "Bearer open")
					source = authenticationhttp.BearerAuthorization()
					if path == "retained" {
						source = legacyhttp.BearerAuthorization()
					}
				}
				if err != nil {
					t.Fatal("constructing static authenticator failed")
				}
				newExtractor := authenticationhttp.NewExtractor
				newMiddleware := authenticationhttp.NewMiddleware
				if path == "retained" {
					newExtractor = legacyhttp.NewExtractor
					newMiddleware = legacyhttp.NewMiddleware
				}
				extractor, err := newExtractor(source)
				if err != nil {
					t.Fatal("constructing extractor failed")
				}
				middleware, err := newMiddleware(extractor, authenticator)
				if err != nil {
					t.Fatal("constructing middleware failed")
				}
				var served bool
				handler := middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					served = true
					principal, ok := authentication.PrincipalFromContext(request.Context())
					if !ok || principal.Subject() != "ordinary" || principal.Method() != kind {
						t.Error("HTTP composition changed the authenticated context")
					}
					writer.WriteHeader(http.StatusNoContent)
				}))
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				if !served || recorder.Code != http.StatusNoContent {
					t.Error("ordinary admitted credential no longer reached the handler")
				}
			})
		}
	}
}

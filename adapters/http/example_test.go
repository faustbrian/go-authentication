package authenticationhttp_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	authentication "github.com/faustbrian/go-authentication/v3"
	authhttp "github.com/faustbrian/go-authentication/v3/adapters/http"
	"github.com/faustbrian/go-authentication/v3/bearer"
)

func ExampleNewMiddleware() {
	extractor, _ := authhttp.NewExtractor(authhttp.BearerAuthorization())
	authenticator, _ := bearer.New(bearer.ValidatorFunc(
		func(_ context.Context, _ string) (authentication.Principal, error) {
			return authentication.NewPrincipal(authentication.PrincipalSpec{
				Subject: "service", Method: "bearer",
			})
		},
	))
	middleware, _ := authhttp.NewMiddleware(extractor, authenticator)
	handler := middleware(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		principal, _ := authentication.PrincipalFromContext(request.Context())
		fmt.Println(principal.Subject())
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer token")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	// Output: service
}

func ExampleWithOptionalAnonymous() {
	extractor, _ := authhttp.NewExtractor(authhttp.BearerAuthorization())
	authenticator, _ := bearer.New(bearer.ValidatorFunc(
		func(context.Context, string) (authentication.Principal, error) {
			return authentication.Principal{}, authentication.NewFailure(authentication.FailureRejected)
		},
	))
	middleware, _ := authhttp.NewMiddleware(extractor, authenticator, authhttp.WithOptionalAnonymous())
	handler := middleware(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		principal, found := authentication.PrincipalFromContext(request.Context())
		fmt.Println(found, principal.IsAnonymous())
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	// Output: true true
}

func ExampleAPIKeySingleHeader() {
	extractor, _ := authhttp.NewExtractor(authhttp.APIKeySingleHeader(
		"X-Api-Key", authhttp.WithAPIKeyMaxBytes(4096), authhttp.WithAPIKeyRejectAuthorization(),
	))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Api-Key", "opaque-key")
	credential, err := extractor.Extract(request)
	apiKey := credential.(authentication.APIKeyCredential)
	fmt.Println(err, apiKey.KeyID() == "", apiKey.Key())

	request.Header.Set("Authorization", "Bearer other")
	_, err = extractor.Extract(request)
	fmt.Println(err)
	// Output:
	// <nil> true opaque-key
	// authentication: ambiguous credentials
}

func ExampleWithFailureWriter() {
	challenge, _ := authentication.NewChallenge("Bearer", map[string]string{"realm": "api"})
	extractor, _ := authhttp.NewExtractor(authhttp.BearerAuthorization())
	authenticator, _ := bearer.New(bearer.ValidatorFunc(
		func(context.Context, string) (authentication.Principal, error) {
			return authentication.Principal{}, authentication.NewFailure(authentication.FailureRejected)
		},
	))
	middleware, _ := authhttp.NewMiddleware(extractor, authenticator,
		authhttp.WithChallenges(challenge),
		authhttp.WithFailureWriter(func(writer http.ResponseWriter, _ *http.Request, status int, _ error) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(status)
			_, _ = writer.Write([]byte(`{"message":"Unauthenticated."}`))
		}),
	)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer unknown")
	recorder := httptest.NewRecorder()
	middleware(http.NotFoundHandler()).ServeHTTP(recorder, request)
	fmt.Println(recorder.Code, recorder.Header().Get("WWW-Authenticate"), recorder.Body.String())
	// Output: 401 Bearer realm="api" {"message":"Unauthenticated."}
}

package authentication_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	authenticationhttp "github.com/faustbrian/go-authentication/v2/adapters/http"
	"github.com/faustbrian/go-authentication/v2/apikey"
	//lint:ignore SA1019 Intentionally exercise the retained facade promised by the migration contract.
	"github.com/faustbrian/go-authentication/v2/authhttp" //nolint:staticcheck // Retained facade compatibility coverage.
	"github.com/faustbrian/go-authentication/v2/basic"
	"github.com/faustbrian/go-authentication/v2/bearer"
)

func TestPrincipalAdmissionDefaultStaticProducers(t *testing.T) {
	spec := authentication.PrincipalSpec{Subject: "sam", Claims: map[string]any{"label": "ops"}}
	basicAuth, err := basic.NewStatic([]basic.Entry{{Username: "sam", Password: "word", Principal: spec}})
	if err != nil {
		t.Fatal("ordinary Basic producer failed")
	}
	keyAuth, err := apikey.NewStatic([]apikey.Entry{{ID: "sam", Key: "word", Principal: spec}})
	if err != nil {
		t.Fatal("ordinary API-key producer failed")
	}
	bearerAuth, err := bearer.NewStatic([]bearer.Entry{{Token: "word", Principal: spec}})
	if err != nil {
		t.Fatal("ordinary bearer producer failed")
	}
	for _, test := range []struct {
		name          string
		authenticator authentication.Authenticator
		credential    authentication.Credential
		method        string
	}{
		{"basic", basicAuth, authentication.NewBasicCredential("sam", "word"), "basic"},
		{"api-key", keyAuth, authentication.NewAPIKeyCredential("sam", "word"), "api_key"},
		{"bearer", bearerAuth, authentication.NewBearerCredential("word"), "bearer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.authenticator.Authenticate(context.Background(), test.credential)
			principal, ok := result.Principal()
			if err != nil || !ok || result.State() != authentication.ResultAuthenticated ||
				principal.Subject() != "sam" || principal.Method() != test.method || !reflect.DeepEqual(principal.Claims(), spec.Claims) {
				t.Fatal("default Principal admission changed ordinary authentication result")
			}
			ctx := authentication.ContextWithPrincipal(context.Background(), principal)
			stored, ok := authentication.PrincipalFromContext(ctx)
			if !ok || !reflect.DeepEqual(stored.Claims(), spec.Claims) {
				t.Fatal("context lost admitted claims")
			}
		})
	}
}

func TestPrincipalAdmissionSmallPolicyHTTPConsumers(t *testing.T) {
	principal, err := authentication.NewPrincipalWithOptions(authentication.PrincipalSpec{
		Subject: "sam", Method: "bearer", Claims: map[string]any{"role": "ops"},
	}, authentication.WithMaxPrincipalStringBytes(6), authentication.WithMaxPrincipalTotalStringBytes(16),
		authentication.WithMaxPrincipalClaimNodes(1))
	if err != nil {
		t.Fatal("small ordinary Principal policy failed")
	}
	authenticator, err := bearer.New(bearer.ValidatorFunc(func(context.Context, string) (authentication.Principal, error) {
		return principal, nil
	}))
	if err != nil {
		t.Fatal("ordinary validator configuration failed")
	}
	canonical, err := authenticationhttp.NewExtractor(authenticationhttp.BearerAuthorization())
	if err != nil {
		t.Fatal("canonical extractor configuration failed")
	}
	canonicalMiddleware, err := authenticationhttp.NewMiddleware(canonical, authenticator)
	if err != nil {
		t.Fatal("canonical middleware configuration failed")
	}
	//lint:ignore SA1019 Intentionally exercise the retained facade promised by the migration contract.
	retained, err := authhttp.NewExtractor(authhttp.BearerAuthorization()) //nolint:staticcheck // Retained facade compatibility coverage.
	if err != nil {
		t.Fatal("retained extractor configuration failed")
	}
	//lint:ignore SA1019 Intentionally exercise the retained facade promised by the migration contract.
	retainedMiddleware, err := authhttp.NewMiddleware(retained, authenticator) //nolint:staticcheck // Retained facade compatibility coverage.
	if err != nil {
		t.Fatal("retained middleware configuration failed")
	}
	for _, test := range []struct {
		name       string
		middleware func(http.Handler) http.Handler
	}{
		{"canonical", canonicalMiddleware}, {"retained", retainedMiddleware},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/", nil)
			if err != nil {
				t.Fatal("ordinary in-memory request failed")
			}
			request.Header.Set("Authorization", "Bearer word")
			called := false
			handler := test.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				stored, ok := authentication.PrincipalFromContext(r.Context())
				if !ok || stored.Subject() != "sam" || stored.Method() != "bearer" ||
					!reflect.DeepEqual(stored.Claims(), map[string]any{"role": "ops"}) {
					t.Error("HTTP context lost admitted identity or claims")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if !called || response.Code != http.StatusNoContent {
				t.Fatal("ordinary HTTP composition changed")
			}
		})
	}
}

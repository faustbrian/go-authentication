package authhttp_test

import (
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"

	authentication "github.com/faustbrian/go-authentication"
	authenticationhttp "github.com/faustbrian/go-authentication/adapters/http"
	legacy "github.com/faustbrian/go-authentication/authhttp"
)

func TestLegacyFacadePreservesHTTPTypeIdentityAndExtraction(t *testing.T) {
	if reflect.TypeOf((*authenticationhttp.Source)(nil)).Elem() != reflect.TypeOf((*legacy.Source)(nil)).Elem() ||
		reflect.TypeOf((*authenticationhttp.Extractor)(nil)) != reflect.TypeOf((*legacy.Extractor)(nil)) ||
		reflect.TypeOf((*authenticationhttp.CredentialExtractor)(nil)).Elem() != reflect.TypeOf((*legacy.CredentialExtractor)(nil)).Elem() ||
		reflect.TypeOf(authenticationhttp.BearerOption(nil)) != reflect.TypeOf(legacy.BearerOption(nil)) ||
		reflect.TypeOf(authenticationhttp.APIKeyOption(nil)) != reflect.TypeOf(legacy.APIKeyOption(nil)) ||
		reflect.TypeOf(authenticationhttp.MiddlewareOption(nil)) != reflect.TypeOf(legacy.MiddlewareOption(nil)) {
		t.Fatal("legacy and successor exported types do not have identical reflection identity")
	}

	request := httptest.NewRequest("GET", "https://example.test/", nil)
	request.Header.Set("Authorization", "Bearer token")
	legacyExtractor, err := legacy.NewExtractor(legacy.BearerAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	successorExtractor, err := authenticationhttp.NewExtractor(authenticationhttp.BearerAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	legacyCredential, legacyErr := legacyExtractor.Extract(request)
	successorCredential, successorErr := successorExtractor.Extract(request)
	if legacyErr != successorErr || reflect.TypeOf(legacyCredential) != reflect.TypeOf(successorCredential) ||
		!reflect.DeepEqual(legacyCredential, successorCredential) {
		t.Fatalf("legacy=(%T, %#v, %v) successor=(%T, %#v, %v)", legacyCredential, legacyCredential, legacyErr, successorCredential, successorCredential, successorErr)
	}

	_, legacyErr = legacy.NewExtractor()
	_, successorErr = authenticationhttp.NewExtractor()
	if !errors.Is(legacyErr, authentication.ErrInvalidConfiguration) || !errors.Is(successorErr, authentication.ErrInvalidConfiguration) || legacyErr.Error() != successorErr.Error() {
		t.Fatalf("legacy error=%v successor error=%v", legacyErr, successorErr)
	}

	challenge, err := authentication.NewChallenge("Bearer", map[string]string{"realm": "api"})
	if err != nil {
		t.Fatal(err)
	}
	legacyChallenge, legacyErr := legacy.FormatChallenge(challenge)
	successorChallenge, successorErr := authenticationhttp.FormatChallenge(challenge)
	if legacyErr != successorErr || legacyChallenge != successorChallenge {
		t.Fatalf("legacy=(%q, %v) successor=(%q, %v)", legacyChallenge, legacyErr, successorChallenge, successorErr)
	}

	_ = legacy.BasicAuthorization()
	_ = legacy.BearerAuthorization(legacy.WithBearerMaxBytes(32), legacy.WithBearerPipe())
	_ = legacy.BearerQuery("token")
	_ = legacy.BearerCookie("token")
	_ = legacy.APIKeyHeader("X-Key-ID", "X-Key", legacy.WithAPIKeyMaxBytes(32))
	_ = legacy.APIKeyQuery("key_id", "key")
	_ = legacy.APIKeyCookie("key_id", "key")
	_ = legacy.WithOptionalAnonymous()
	_ = legacy.WithChallenges(challenge)
	if middleware, err := legacy.NewMiddleware(nil, nil); middleware != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("middleware nil=%v error=%v", middleware == nil, err)
	}
}

package apikey_test

import (
	"context"
	"errors"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authentication/v2/apikey"
)

func TestStaticByteAdmission(t *testing.T) {
	options := []apikey.Option{apikey.WithMaxKeyIDBytes(4), apikey.WithMaxKeyBytes(4)}
	authenticator, err := apikey.NewStaticWithOptions([]apikey.Entry{{
		ID: "name", Key: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
	}}, options...)
	if err != nil {
		t.Fatal("inclusive credential limit was refused")
	}
	result, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open"))
	principal, ok := result.Principal()
	if err != nil || !ok || principal.Subject() != "ordinary" || principal.Method() != "api_key" {
		t.Fatal("inclusive credential limit changed authentication")
	}
	for _, test := range []struct{ name, id, key string }{
		{"identifier", "names", "open"},
		{"key", "name", "opens"},
		{"identifier bytes", "été", "open"},
		{"key bytes", "name", "été"},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := []apikey.Entry{{ID: test.id, Key: test.key, Principal: authentication.PrincipalSpec{Subject: "ordinary"}}}
			if candidate, err := apikey.NewStaticWithOptions(entries, options...); candidate != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
				t.Error("over-limit configuration was not refused")
			} else if err.Error() != authentication.ErrInvalidConfiguration.Error()+": API-key credential size" {
				t.Error("configuration error did not use the fixed size message")
			}
			result, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential(test.id, test.key))
			var failure *authentication.Failure
			if _, authenticated := result.Principal(); authenticated || !errors.As(err, &failure) ||
				failure.Kind() != authentication.FailureInvalid || !errors.Is(err, authentication.ErrCredentialsInvalid) {
				t.Error("over-limit request was not a structured invalid failure")
			} else if err.Error() != authentication.ErrCredentialsInvalid.Error() {
				t.Error("request failure did not use the fixed invalid message")
			}
		})
	}
	if _, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("peer", "open")); !errors.Is(err, authentication.ErrCredentialsRejected) {
		t.Error("unknown admitted credential did not remain rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = authenticator.Authenticate(ctx, authentication.NewAPIKeyCredential("names", "opens"))
	if !errors.Is(err, authentication.ErrAuthenticationUnavailable) || !errors.Is(err, context.Canceled) {
		t.Error("size admission changed cancellation precedence or identity")
	}
}

func TestStaticByteReplacementIsAtomic(t *testing.T) {
	for _, test := range []struct{ name, id, key string }{
		{"identifier", "names", "next"},
		{"key", "next", "opens"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator, err := apikey.NewStaticWithOptions([]apikey.Entry{{
				ID: "name", Key: "open", Principal: authentication.PrincipalSpec{Subject: "previous"},
			}}, apikey.WithMaxKeyIDBytes(4), apikey.WithMaxKeyBytes(4))
			if err != nil {
				t.Fatal("constructing authenticator failed")
			}
			if err := authenticator.Replace([]apikey.Entry{
				{ID: "warm", Key: "calm", Principal: authentication.PrincipalSpec{Subject: "candidate"}},
				{ID: test.id, Key: test.key, Principal: authentication.PrincipalSpec{Subject: "refused"}},
			}); !errors.Is(err, authentication.ErrInvalidConfiguration) {
				t.Error("over-limit replacement was not refused")
			}
			result, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open"))
			principal, ok := result.Principal()
			if err != nil || !ok || principal.Subject() != "previous" {
				t.Error("refused replacement changed the active set")
			}
			if _, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential(test.id, test.key)); !errors.Is(err, authentication.ErrCredentialsInvalid) {
				t.Error("refused replacement changed request admission")
			}
			if _, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("warm", "calm")); !errors.Is(err, authentication.ErrCredentialsRejected) {
				t.Error("refused replacement published an admitted prefix")
			}
			if err := authenticator.Replace([]apikey.Entry{{
				ID: "next", Key: "also", Principal: authentication.PrincipalSpec{Subject: "current"},
			}}); err != nil {
				t.Fatal("later admitted replacement failed")
			}
			result, err = authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("next", "also"))
			principal, ok = result.Principal()
			if err != nil || !ok || principal.Subject() != "current" {
				t.Error("later admitted replacement did not become active")
			}
			if _, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open")); !errors.Is(err, authentication.ErrCredentialsRejected) {
				t.Error("successful replacement retained the old set")
			}
		})
	}
}

func TestStaticByteOptionsDoNotRestrictCallbackConfiguration(t *testing.T) {
	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{Subject: "ordinary", Method: "api_key"})
	if err != nil {
		t.Fatal("constructing principal failed")
	}
	authenticator, err := apikey.New(apikey.ValidatorFunc(func(context.Context, string, string) (authentication.Principal, error) {
		return principal, nil
	}), apikey.WithMaxKeyIDBytes(257), apikey.WithMaxKeyBytes(8*1024+1))
	if err != nil {
		t.Fatal("static ceilings changed existing callback configuration")
	}
	result, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open"))
	got, ok := result.Principal()
	if err != nil || !ok || got.Subject() != "ordinary" || got.Method() != "api_key" {
		t.Error("static ceilings changed ordinary callback authentication")
	}
}

func TestStaticByteDefaultsPreserveZeroValueAndOptions(t *testing.T) {
	entries := []apikey.Entry{{ID: "name", Key: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"}}}
	for _, test := range []struct {
		maximum int
		option  func(int) apikey.Option
	}{
		{0, apikey.WithMaxKeyIDBytes}, {-1, apikey.WithMaxKeyIDBytes}, {257, apikey.WithMaxKeyIDBytes},
		{0, apikey.WithMaxKeyBytes}, {-1, apikey.WithMaxKeyBytes}, {8*1024 + 1, apikey.WithMaxKeyBytes},
	} {
		if authenticator, err := apikey.NewStaticWithOptions(entries, test.option(test.maximum)); authenticator != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
			t.Error("invalid byte-limit option was accepted")
		}
	}
	for _, construct := range []func([]apikey.Entry) (*apikey.Static, error){
		apikey.NewStatic,
		func(entries []apikey.Entry) (*apikey.Static, error) {
			return apikey.NewStaticWithOptions(entries, nil, apikey.WithMaxKeyIDBytes(256), apikey.WithMaxKeyBytes(8*1024))
		},
	} {
		authenticator, err := construct(entries)
		if err != nil {
			t.Fatal("default ceiling configuration was refused")
		}
		if _, err := authenticator.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open")); err != nil {
			t.Error("default constructor changed ordinary authentication")
		}
	}
	var zero apikey.Static
	if _, err := zero.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open")); !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
		t.Error("uninitialized static authenticator did not remain unavailable")
	}
	if err := zero.Replace(entries); err != nil {
		t.Fatal("zero-value installation failed")
	}
	if _, err := zero.Authenticate(context.Background(), authentication.NewAPIKeyCredential("name", "open")); err != nil {
		t.Error("zero-value installation did not authenticate")
	}
	minimum, err := apikey.NewStaticWithOptions([]apikey.Entry{{
		ID: "i", Key: "k", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
	}}, apikey.WithMaxKeyIDBytes(1), apikey.WithMaxKeyBytes(1))
	if err != nil {
		t.Fatal("minimum positive limit was refused")
	}
	if _, err := minimum.Authenticate(context.Background(), authentication.NewAPIKeyCredential("i", "k")); err != nil {
		t.Error("minimum positive limit changed authentication")
	}
}

// The public Static type remains usable as a map key.
var _ = map[apikey.Static]struct{}{}

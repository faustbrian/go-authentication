package basic_test

import (
	"context"
	"errors"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authentication/v2/basic"
)

func TestStaticByteAdmission(t *testing.T) {
	options := []basic.Option{basic.WithMaxUsernameBytes(4), basic.WithMaxPasswordBytes(4)}
	authenticator, err := basic.NewStaticWithOptions([]basic.Entry{{
		Username: "user", Password: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
	}}, options...)
	if err != nil {
		t.Fatal("inclusive credential limit was refused")
	}
	result, err := authenticator.Authenticate(context.Background(), authentication.NewBasicCredential("user", "open"))
	principal, ok := result.Principal()
	if err != nil || !ok || principal.Subject() != "ordinary" || principal.Method() != "basic" {
		t.Fatal("inclusive credential limit changed authentication")
	}
	for _, test := range []struct{ name, username, password string }{
		{"username", "users", "open"},
		{"password", "user", "opens"},
		{"username bytes", "été", "open"},
		{"password bytes", "user", "été"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := basic.NewStaticWithOptions([]basic.Entry{{
				Username: test.username, Password: test.password,
				Principal: authentication.PrincipalSpec{Subject: "ordinary"},
			}}, options...)
			if candidate != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
				t.Error("over-limit configuration was not refused")
			} else if err.Error() != authentication.ErrInvalidConfiguration.Error()+": Basic credential size" {
				t.Error("configuration error did not use the fixed size message")
			}
			result, err := authenticator.Authenticate(context.Background(), authentication.NewBasicCredential(test.username, test.password))
			var failure *authentication.Failure
			if _, authenticated := result.Principal(); authenticated || !errors.As(err, &failure) ||
				failure.Kind() != authentication.FailureInvalid || !errors.Is(err, authentication.ErrCredentialsInvalid) {
				t.Error("over-limit request was not a structured invalid failure")
			} else if err.Error() != authentication.ErrCredentialsInvalid.Error() {
				t.Error("request failure did not use the fixed invalid message")
			}
		})
	}
	if _, err := authenticator.Authenticate(context.Background(), authentication.NewBasicCredential("peer", "open")); !errors.Is(err, authentication.ErrCredentialsRejected) {
		t.Error("unknown admitted credential did not remain rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = authenticator.Authenticate(ctx, authentication.NewBasicCredential("users", "opens"))
	if !errors.Is(err, authentication.ErrAuthenticationUnavailable) || !errors.Is(err, context.Canceled) {
		t.Error("size admission changed cancellation precedence or identity")
	}
}

func TestStaticByteOptionsRejectInvalidLimits(t *testing.T) {
	entries := []basic.Entry{{Username: "user", Password: "open", Principal: authentication.PrincipalSpec{Subject: "ordinary"}}}
	for _, maximum := range []int{0, -1, 8*1024 + 1} {
		for _, option := range []basic.Option{basic.WithMaxUsernameBytes(maximum), basic.WithMaxPasswordBytes(maximum)} {
			if authenticator, err := basic.NewStaticWithOptions(entries, option); authenticator != nil || !errors.Is(err, authentication.ErrInvalidConfiguration) {
				t.Error("invalid byte-limit option was accepted")
			}
		}
	}
	for _, construct := range []func([]basic.Entry) (*basic.Static, error){
		basic.NewStatic,
		func(entries []basic.Entry) (*basic.Static, error) {
			return basic.NewStaticWithOptions(entries, nil, basic.WithMaxUsernameBytes(8*1024), basic.WithMaxPasswordBytes(8*1024))
		},
	} {
		authenticator, err := construct(entries)
		if err != nil {
			t.Fatal("default ceiling configuration was refused")
		}
		if _, err := authenticator.Authenticate(context.Background(), authentication.NewBasicCredential("user", "open")); err != nil {
			t.Error("default constructor changed ordinary authentication")
		}
	}
	minimum, err := basic.NewStaticWithOptions([]basic.Entry{{
		Username: "u", Password: "p", Principal: authentication.PrincipalSpec{Subject: "ordinary"},
	}}, basic.WithMaxUsernameBytes(1), basic.WithMaxPasswordBytes(1))
	if err != nil {
		t.Fatal("minimum positive limit was refused")
	}
	if _, err := minimum.Authenticate(context.Background(), authentication.NewBasicCredential("u", "p")); err != nil {
		t.Error("minimum positive limit changed authentication")
	}
	var zero basic.Static
	if _, err := zero.Authenticate(context.Background(), authentication.NewBasicCredential("u", "p")); !errors.Is(err, authentication.ErrCredentialsRejected) {
		t.Error("zero-value static changed its ordinary rejection behavior")
	}
}

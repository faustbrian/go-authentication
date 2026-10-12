package apikey_test

import (
	"context"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authentication/v2/apikey"
)

// BenchmarkStaticAuthenticate measures one-entry ID/key hashing/comparison; construction and
// credential setup are excluded, with success checks in the measured loop.
func BenchmarkStaticAuthenticate(b *testing.B) {
	authenticator, err := apikey.NewStatic([]apikey.Entry{{
		ID: "primary", Key: "secret",
		Principal: authentication.PrincipalSpec{Subject: "service"},
	}})
	if err != nil {
		b.Fatalf("NewStatic() error = %v", err)
	}
	credential := authentication.NewAPIKeyCredential("primary", "secret")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := authenticator.Authenticate(context.Background(), credential); err != nil {
			b.Fatal(err)
		}
	}
}

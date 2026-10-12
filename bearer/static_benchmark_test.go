package bearer_test

import (
	"context"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authentication/v2/bearer"
)

// BenchmarkStaticAuthenticate measures a two-entry rotation-overlap snapshot matching the older
// token; setup is excluded, so do not compare directly to one-entry workloads.
func BenchmarkStaticAuthenticate(b *testing.B) {
	authenticator, err := bearer.NewStatic([]bearer.Entry{
		{Token: "current", Principal: authentication.PrincipalSpec{Subject: "service"}},
		{Token: "previous", Principal: authentication.PrincipalSpec{Subject: "service"}},
	})
	if err != nil {
		b.Fatalf("NewStatic() error = %v", err)
	}
	credential := authentication.NewBearerCredential("previous")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := authenticator.Authenticate(context.Background(), credential); err != nil {
			b.Fatal(err)
		}
	}
}

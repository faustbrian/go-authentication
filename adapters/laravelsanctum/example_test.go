package laravelsanctum_test

import (
	"context"
	"crypto/sha256"
	"fmt"

	authentication "github.com/faustbrian/go-authentication/v3"
	"github.com/faustbrian/go-authentication/v3/adapters/laravelsanctum"
	"github.com/faustbrian/go-authentication/v3/bearer"
)

func ExampleNewValidator() {
	stored := sha256.Sum256([]byte("secret"))
	validator, _ := laravelsanctum.NewValidator(laravelsanctum.ResolverFunc(
		func(_ context.Context, token laravelsanctum.Token) (authentication.Principal, error) {
			id, byID := token.ID()
			if !byID || id != "42" || !token.Matches(stored[:]) {
				return authentication.Principal{}, authentication.NewFailure(authentication.FailureRejected)
			}
			return authentication.NewPrincipal(authentication.PrincipalSpec{Subject: "user-42", Method: "bearer"})
		},
	))
	authenticator, _ := bearer.New(validator)
	result, err := authenticator.Authenticate(context.Background(), authentication.NewBearerCredential("0042|secret"))
	principal, _ := result.Principal()
	fmt.Println(err, principal.Subject())

	_, err = authenticator.Authenticate(context.Background(), authentication.NewBearerCredential("0|secret"))
	fmt.Println(err)
	// Output:
	// <nil> user-42
	// authentication: credentials rejected
}

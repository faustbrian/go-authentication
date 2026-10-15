package authentication_test

import (
	"fmt"
	auth "github.com/faustbrian/go-authentication/v2"
	"time"
)

func ExampleProof_Validate() {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	proof, err := auth.NewProof(auth.ProofSpec{
		ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "subject",
		Method: "password", Assurance: auth.AssuranceSingleFactor,
		Purpose: "change-password", Audience: "account-service",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		panic(err)
	}
	err = proof.Validate(auth.ProofUse{Tenant: "tenant", Subject: "subject", Purpose: "change-password", Audience: "account-service", Now: now})
	fmt.Println(err == nil)
	fmt.Println(auth.AssuranceMultiFactor.AtLeast(auth.AssuranceSingleFactor))
	// Output:
	// true
	// true
}

package authentication_test

import (
	"errors"
	"reflect"
	"testing"

	authentication "github.com/faustbrian/go-authentication"
)

func TestPrincipalAdmissionAdditionalTotalStringOwners(t *testing.T) {
	// Each row independently protects aggregate charging by one retention owner;
	// no individual string, list count or claim-node ceiling is approached.
	tests := []struct {
		name          string
		spec          authentication.PrincipalSpec
		inclusive     int
		refusedBudget int
	}{
		{
			name: "subject", spec: authentication.PrincipalSpec{Subject: "sam", Method: "b"},
			inclusive: 4, refusedBudget: 2,
		},
		{
			name: "method", spec: authentication.PrincipalSpec{Subject: "a", Method: "api"},
			inclusive: 4, refusedBudget: 3,
		},
		{
			name: "audiences", spec: authentication.PrincipalSpec{Subject: "a", Method: "b", Audiences: []string{"app"}},
			inclusive: 5, refusedBudget: 4,
		},
		{
			name: "tenant hints", spec: authentication.PrincipalSpec{Subject: "a", Method: "b", TenantHints: []string{"app"}},
			inclusive: 5, refusedBudget: 4,
		},
		{
			name: "scopes", spec: authentication.PrincipalSpec{Subject: "a", Method: "b", Scopes: []string{"app"}},
			inclusive: 5, refusedBudget: 4,
		},
		{
			name: "top claim key", spec: authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{"key": true}},
			inclusive: 5, refusedBudget: 4,
		},
		{
			name: "nested claim key", spec: authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{"c": map[string]any{"key": true}}},
			inclusive: 6, refusedBudget: 5,
		},
		{
			name: "scalar claim string", spec: authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{"c": "ops"}},
			inclusive: 6, refusedBudget: 5,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal, err := authentication.NewPrincipalWithOptions(test.spec,
				authentication.WithMaxPrincipalTotalStringBytes(test.inclusive))
			if err != nil || principal.IsAnonymous() || principal.Subject() != test.spec.Subject ||
				principal.Method() != test.spec.Method ||
				!reflect.DeepEqual(principal.Audiences(), test.spec.Audiences) ||
				!reflect.DeepEqual(principal.TenantHints(), test.spec.TenantHints) ||
				!reflect.DeepEqual(principal.Scopes(), test.spec.Scopes) ||
				!reflect.DeepEqual(principal.Claims(), test.spec.Claims) {
				t.Fatal("inclusive aggregate budget did not preserve ordinary identity data")
			}
			// Subject is first, but Method must also be nonempty: total-minus-one
			// would exhaust later. Its refusal budget is one below Subject alone.
			principal, err = authentication.NewPrincipalWithOptions(test.spec,
				authentication.WithMaxPrincipalTotalStringBytes(test.refusedBudget))
			assertAdditionalPrincipalAdmissionRefusal(t, principal, err,
				"authentication: invalid principal: principal total string size exceeded")
		})
	}
}

func TestPrincipalAdmissionAdditionalTopLevelScalarNodes(t *testing.T) {
	// Three scalar output occurrences require three shared nodes regardless of
	// map iteration order; root-map size admission must not omit this accounting.
	spec := authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{
		"a": 1, "b": true, "c": nil,
	}}
	principal, err := authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(3))
	want := map[string]any{"a": 1, "b": true, "c": nil}
	if err != nil || principal.IsAnonymous() || !reflect.DeepEqual(principal.Claims(), want) {
		t.Fatal("inclusive top-level scalar node budget changed ordinary claims")
	}
	principal, err = authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(2))
	assertAdditionalPrincipalAdmissionRefusal(t, principal, err,
		"authentication: invalid principal: principal claim node count exceeded")
}

func TestPrincipalAdmissionAdditionalRecursiveRemainingNodes(t *testing.T) {
	// The outer array, nested array, scalar and final nil are four occurrences.
	// The immediate lengths fit three nodes, but descendants exhaust the shared
	// budget before the final nil; it must not escape admission or be dropped.
	spec := authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{
		"c": [2]any{[1]int{1}, nil},
	}}
	principal, err := authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(4))
	want := map[string]any{"c": []any{[]any{1}, nil}}
	if err != nil || principal.IsAnonymous() || !reflect.DeepEqual(principal.Claims(), want) {
		t.Fatal("inclusive recursive node budget changed normalized claims")
	}
	principal, err = authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(3))
	assertAdditionalPrincipalAdmissionRefusal(t, principal, err,
		"authentication: invalid principal: principal claim node count exceeded")
}

func assertAdditionalPrincipalAdmissionRefusal(t *testing.T, principal authentication.Principal, err error, want string) {
	t.Helper()
	if !errors.Is(err, authentication.ErrInvalidPrincipal) || !principal.IsAnonymous() ||
		!reflect.DeepEqual(principal, authentication.AnonymousPrincipal()) {
		t.Fatal("aggregate refusal did not return the safe sentinel and empty anonymous identity")
	}
	if err.Error() != want {
		t.Fatal("aggregate refusal disclosed unexpected error detail")
	}
}

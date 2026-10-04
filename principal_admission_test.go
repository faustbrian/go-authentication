package authentication_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
)

type principalLabel string

func TestPrincipalAdmissionIndividualStrings(t *testing.T) {
	tests := []struct {
		name string
		set  func(*authentication.PrincipalSpec, string)
	}{
		{"subject", func(s *authentication.PrincipalSpec, v string) { s.Subject = v }},
		{"method", func(s *authentication.PrincipalSpec, v string) { s.Method = v }},
		{"issuer", func(s *authentication.PrincipalSpec, v string) { s.Issuer = v }},
		{"audience", func(s *authentication.PrincipalSpec, v string) { s.Audiences = []string{v} }},
		{"tenant", func(s *authentication.PrincipalSpec, v string) { s.TenantHints = []string{v} }},
		{"scope", func(s *authentication.PrincipalSpec, v string) { s.Scopes = []string{v} }},
		{"claim name", func(s *authentication.PrincipalSpec, v string) { s.Claims = map[string]any{v: true} }},
		{"nested claim name", func(s *authentication.PrincipalSpec, v string) {
			s.Claims = map[string]any{"key": map[principalLabel]any{principalLabel(v): true}}
		}},
		{"claim string", func(s *authentication.PrincipalSpec, v string) { s.Claims = map[string]any{"key": v} }},
		{"defined claim string", func(s *authentication.PrincipalSpec, v string) {
			s.Claims = map[string]any{"key": principalLabel(v)}
		}},
		{"number string", func(s *authentication.PrincipalSpec, v string) {
			s.Claims = map[string]any{"key": json.Number(v)}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := authentication.PrincipalSpec{Subject: "sam", Method: "api"}
			test.set(&spec, "123")
			principal, err := authentication.NewPrincipalWithOptions(spec,
				authentication.WithMaxPrincipalStringBytes(3))
			if err != nil || principal.IsAnonymous() {
				t.Fatal("inclusive ordinary string was not admitted")
			}
			test.set(&spec, "1234")
			principal, err = authentication.NewPrincipalWithOptions(spec,
				authentication.WithMaxPrincipalStringBytes(3))
			assertPrincipalAdmissionError(t, principal, err, "principal string size exceeded")
		})
	}
}

func TestPrincipalAdmissionIdentityListCounts(t *testing.T) {
	tests := []struct {
		name string
		set  func(*authentication.PrincipalSpec, []string)
	}{
		{"audiences", func(s *authentication.PrincipalSpec, v []string) { s.Audiences = v }},
		{"tenants", func(s *authentication.PrincipalSpec, v []string) { s.TenantHints = v }},
		{"scopes", func(s *authentication.PrincipalSpec, v []string) { s.Scopes = v }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := authentication.PrincipalSpec{Subject: "sam", Method: "api"}
			test.set(&spec, []string{"a", "b"})
			principal, err := authentication.NewPrincipalWithOptions(spec,
				authentication.WithMaxPrincipalIdentityEntries(2))
			if err != nil || principal.IsAnonymous() {
				t.Fatal("inclusive ordinary identity list was not admitted")
			}
			test.set(&spec, []string{"a", "b", "c"})
			principal, err = authentication.NewPrincipalWithOptions(spec,
				authentication.WithMaxPrincipalIdentityEntries(2))
			assertPrincipalAdmissionError(t, principal, err, "principal identity list size exceeded")
		})
	}
	principal, err := authentication.NewPrincipalWithOptions(authentication.PrincipalSpec{
		Subject: "sam", Method: "api", Audiences: []string{"a", "b"},
		TenantHints: []string{"c", "d"}, Scopes: []string{"e", "f"},
	}, authentication.WithMaxPrincipalIdentityEntries(2))
	if err != nil || len(principal.Audiences()) != 2 || len(principal.TenantHints()) != 2 || len(principal.Scopes()) != 2 {
		t.Fatal("identity list counts must be independent")
	}
}

func TestPrincipalAdmissionSharedStringBudget(t *testing.T) {
	// Eleven retained one-byte occurrences span every string owner.
	spec := authentication.PrincipalSpec{
		Subject: "a", Method: "b", Issuer: "c", Audiences: []string{"d"},
		TenantHints: []string{"e"}, Scopes: []string{"f"},
		Claims: map[string]any{"g": map[string]any{"h": principalLabel("i")}, "j": []any{json.Number("1")}},
	}
	principal, err := authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalTotalStringBytes(11))
	if err != nil || !reflect.DeepEqual(principal.Claims(), spec.Claims) {
		t.Fatal("inclusive shared string budget did not preserve claims")
	}
	spec.Issuer = "cc"
	principal, err = authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalTotalStringBytes(11))
	assertPrincipalAdmissionError(t, principal, err, "principal total string size exceeded")
}

func TestPrincipalAdmissionRepeatedStringOccurrences(t *testing.T) {
	shared := map[string]any{"x": "y"}
	spec := authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{"c": shared, "d": shared}}
	principal, err := authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalTotalStringBytes(8))
	if err != nil || !reflect.DeepEqual(principal.Claims(), spec.Claims) {
		t.Fatal("inclusive repeated occurrence budget did not preserve claims")
	}
	principal, err = authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalTotalStringBytes(7))
	assertPrincipalAdmissionError(t, principal, err, "principal total string size exceeded")
}

func TestPrincipalAdmissionSharedClaimNodes(t *testing.T) {
	// Six values: nil, array plus two scalars, map plus its scalar.
	spec := authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{
		"a": nil, "b": [2]any{1, 2}, "c": map[string]any{"d": true},
	}}
	principal, err := authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(6))
	want := map[string]any{"a": nil, "b": []any{1, 2}, "c": map[string]any{"d": true}}
	if err != nil || !reflect.DeepEqual(principal.Claims(), want) {
		t.Fatal("inclusive claim budget changed normalization or counted interface wrappers")
	}
	spec.Claims["e"] = 3
	principal, err = authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(6))
	assertPrincipalAdmissionError(t, principal, err, "principal claim node count exceeded")
}

func TestPrincipalAdmissionRepeatedClaimNodes(t *testing.T) {
	shared := []any{1}
	spec := authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{"c": shared, "d": shared}}
	principal, err := authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(4))
	if err != nil || !reflect.DeepEqual(principal.Claims(), spec.Claims) {
		t.Fatal("inclusive repeated node budget did not preserve claims")
	}
	principal, err = authentication.NewPrincipalWithOptions(spec,
		authentication.WithMaxPrincipalClaimNodes(3))
	assertPrincipalAdmissionError(t, principal, err, "principal claim node count exceeded")
}

func TestPrincipalAdmissionImmediateCollections(t *testing.T) {
	for name, value := range map[string]any{
		"map":   map[string]any{"a": 1, "b": 2},
		"slice": []any{1, 2}, "array": [2]int{1, 2},
	} {
		t.Run(name, func(t *testing.T) {
			spec := authentication.PrincipalSpec{Subject: "a", Method: "b", Claims: map[string]any{"c": value}}
			principal, err := authentication.NewPrincipalWithOptions(spec,
				authentication.WithMaxPrincipalClaimNodes(3))
			if err != nil || len(principal.Claims()) != 1 {
				t.Fatal("inclusive immediate collection was not admitted")
			}
			principal, err = authentication.NewPrincipalWithOptions(spec,
				authentication.WithMaxPrincipalClaimNodes(2))
			assertPrincipalAdmissionError(t, principal, err, "principal claim node count exceeded")
		})
	}
}

func TestPrincipalAdmissionOptionsRejectUnsafeConfiguration(t *testing.T) {
	options := []struct {
		name    string
		option  func(int) authentication.PrincipalOption
		ceiling int
	}{
		{"string", authentication.WithMaxPrincipalStringBytes, authentication.MaxPrincipalStringBytes},
		{"list", authentication.WithMaxPrincipalIdentityEntries, authentication.MaxPrincipalIdentityEntries},
		{"bytes", authentication.WithMaxPrincipalTotalStringBytes, authentication.MaxPrincipalTotalStringBytes},
		{"nodes", authentication.WithMaxPrincipalClaimNodes, authentication.MaxPrincipalClaimNodes},
	}
	for _, test := range options {
		for _, limit := range []int{-1, 0, test.ceiling + 1} {
			t.Run(test.name, func(t *testing.T) {
				principal, err := authentication.NewPrincipalWithOptions(authentication.PrincipalSpec{Subject: "a", Method: "b"}, test.option(limit))
				if !principal.IsAnonymous() || !errors.Is(err, authentication.ErrInvalidPrincipal) || !errors.Is(err, authentication.ErrInvalidConfiguration) {
					t.Fatal("unsafe configuration did not return both safe public sentinels")
				}
				if err.Error() != "authentication: invalid principal: authentication: invalid configuration: principal limits" {
					t.Fatal("configuration error contains unexpected detail")
				}
			})
		}
	}
}

func TestPrincipalAdmissionPreservesTypesAndDefensiveCopies(t *testing.T) {
	location := time.FixedZone("app", 3600)
	authenticatedAt := time.Date(2026, time.July, 15, 7, 0, 0, 0, location)
	shared := []any{principalLabel("eu")}
	claims := map[string]any{
		"label": principalLabel("ops"), "number": json.Number("12"),
		"array": [2]int{1, 2}, "nil": nil, "map": map[string]any(nil),
		"slice": []string(nil), "first": shared, "second": shared,
	}
	audiences, tenants, scopes := []string{"app"}, []string{"eu"}, []string{"read"}
	principal, err := authentication.NewPrincipalWithOptions(authentication.PrincipalSpec{
		Subject: "sam", Method: "api", Issuer: "home", Audiences: audiences,
		TenantHints: tenants, Scopes: scopes, Claims: claims, AuthenticatedAt: authenticatedAt,
	}, nil, authentication.WithMaxPrincipalStringBytes(8), authentication.WithMaxPrincipalIdentityEntries(1),
		authentication.WithMaxPrincipalTotalStringBytes(70), authentication.WithMaxPrincipalClaimNodes(12))
	if err != nil {
		t.Fatal("ordinary typed principal was not admitted")
	}
	want := map[string]any{
		"label": principalLabel("ops"), "number": json.Number("12"),
		"array": []any{1, 2}, "nil": nil, "map": map[string]any{},
		"slice": []any{}, "first": []any{principalLabel("eu")}, "second": []any{principalLabel("eu")},
	}
	if !reflect.DeepEqual(principal.Claims(), want) {
		t.Fatal("typed strings or normalized claim shapes changed")
	}
	if principal.AuthenticatedAt() != authenticatedAt || principal.AuthenticatedAt().Location() != location {
		t.Fatal("trusted timestamp representation changed")
	}
	audiences[0], tenants[0], scopes[0] = "new", "new", "new"
	shared[0] = principalLabel("new")
	claims["number"] = json.Number("34")
	returned := principal.Claims()
	returned["first"].([]any)[0] = principalLabel("new")
	if !reflect.DeepEqual(returned["second"], want["second"]) {
		t.Fatal("repeated input references were not copied independently")
	}
	returned["array"].([]any)[0] = 3
	returned["map"].(map[string]any)["new"] = 1
	principal.Audiences()[0] = "new"
	principal.TenantHints()[0] = "new"
	principal.Scopes()[0] = "new"
	if !reflect.DeepEqual(principal.Claims(), want) || !reflect.DeepEqual(principal.Audiences(), []string{"app"}) ||
		!reflect.DeepEqual(principal.TenantHints(), []string{"eu"}) || !reflect.DeepEqual(principal.Scopes(), []string{"read"}) {
		t.Fatal("caller mutation changed retained identity or claims")
	}
}

func TestPrincipalAdmissionDefaultsAndAnonymous(t *testing.T) {
	spec := authentication.PrincipalSpec{Subject: "sam", Method: "api", Claims: map[string]any{"label": "ops"}}
	legacy, err := authentication.NewPrincipal(spec)
	if err != nil {
		t.Fatal("default constructor rejected ordinary principal")
	}
	configured, err := authentication.NewPrincipalWithOptions(spec, nil)
	if err != nil || !reflect.DeepEqual(legacy, configured) {
		t.Fatal("default constructor semantics differ")
	}
	var zero authentication.Principal
	for _, principal := range []authentication.Principal{zero, authentication.AnonymousPrincipal()} {
		if !principal.IsAnonymous() || principal.Claims() != nil || principal.Audiences() != nil || principal.TenantHints() != nil || principal.Scopes() != nil {
			t.Fatal("anonymous zero-value semantics changed")
		}
	}
}

func assertPrincipalAdmissionError(t *testing.T, principal authentication.Principal, err error, detail string) {
	t.Helper()
	if !errors.Is(err, authentication.ErrInvalidPrincipal) || !principal.IsAnonymous() {
		t.Fatal("one-over ordinary principal was not refused with ErrInvalidPrincipal")
	}
	if err.Error() != "authentication: invalid principal: "+detail {
		t.Fatal("admission error contains unexpected detail")
	}
}

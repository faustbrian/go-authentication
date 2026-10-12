package authentication_test

import (
	"encoding/json"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
)

// FuzzPrincipalClaims exercises bounded JSON-derived claim graphs through admission and copy;
// rejected inputs return and accepted outputs are copied, without a full
// confidentiality or principal-semantics oracle.
func FuzzPrincipalClaims(f *testing.F) {
	f.Add([]byte(`{"tenant":"north","groups":["operator"]}`))
	f.Add([]byte(`{"nested":{"one":{"two":true}}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 64*1024 {
			t.Skip()
		}
		var claims map[string]any
		if err := json.Unmarshal(encoded, &claims); err != nil {
			return
		}
		principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{
			Subject: "fuzz", Method: "test", Claims: claims,
		})
		if err != nil {
			return
		}
		_ = principal.Claims()
	})
}

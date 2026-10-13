package jwt

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authentication/authtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestMalformedJSONSuffixNeverAdmitsKeyProvider(t *testing.T) {
	for _, suffix := range []string{"#", "{", "true", " null"} {
		for _, section := range []string{"header", "claims"} {
			t.Run(section+suffix, func(t *testing.T) {
				calls := 0
				validator, err := New(Config{
					Issuer: "https://issuer.example.test", Audience: "orders",
					Algorithms: []jwa.SignatureAlgorithm{jwa.HS256()},
					Clock:      authtest.NewClock(time.Unix(1_800_000_000, 0)),
					Provider: KeyProviderFunc(func(context.Context) (jwk.Set, error) {
						calls++
						return nil, ErrKeyProviderUnavailable
					}),
				})
				if err != nil {
					t.Fatal(err)
				}
				header, claims := `{"alg":"HS256","kid":"key"}`, `{}`
				if section == "header" {
					header += suffix
				} else {
					claims += suffix
				}
				token := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
					base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".AQ"
				if _, err := validator.ValidateBearer(context.Background(), token); !errors.Is(err, authentication.ErrCredentialsRejected) {
					t.Errorf("malformed JSON classification = %v; want rejected", err)
				}
				if calls != 0 {
					t.Errorf("malformed JSON invoked key provider %d times", calls)
				}
				valid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"key"}`)) + ".e30.AQ"
				if _, err := validator.ValidateBearer(context.Background(), valid); !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
					t.Errorf("valid JSON provider failure = %v; want unavailable", err)
				}
				if calls != 1 {
					t.Errorf("valid JSON control provider calls = %d; want 1", calls)
				}
			})
		}
	}
}

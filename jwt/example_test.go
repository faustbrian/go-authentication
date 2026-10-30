package jwt_test

import (
	"context"
	"fmt"
	"time"

	authjwt "github.com/faustbrian/go-authentication/jwt/v2"
	"github.com/faustbrian/go-authentication/v3/authtest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	upstreamjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleNew() {
	key, err := jwk.Import([]byte("01234567890123456789012345678901"))
	if err != nil {
		return
	}
	_ = key.Set(jwk.KeyIDKey, "key")
	_ = key.Set(jwk.AlgorithmKey, jwa.HS256())
	keys := jwk.NewSet()
	_ = keys.AddKey(key)
	now := time.Unix(1_800_000_000, 0).UTC()
	validator, err := authjwt.New(authjwt.Config{
		Issuer: "https://issuer.example.test", Audience: "service",
		Algorithms: []jwa.SignatureAlgorithm{jwa.HS256()}, KeySet: keys,
		Clock: authtest.NewClock(now),
	})
	if err != nil {
		return
	}
	token := upstreamjwt.New()
	_ = token.Set("sub", "service")
	_ = token.Set("iss", "https://issuer.example.test")
	_ = token.Set("aud", "service")
	_ = token.Set("iat", now)
	_ = token.Set("exp", now.Add(time.Hour))
	signed, _ := upstreamjwt.Sign(token, upstreamjwt.WithKey(jwa.HS256(), key))
	principal, err := validator.ValidateBearer(context.Background(), string(signed))
	fmt.Println(err, principal.Subject())
	// Output: <nil> service
}

func ExampleRemoteSettings_Validate() {
	settings := authjwt.RemoteSettings{
		Issuer: "https://identity.example", Audience: "service",
		JWKURL: "https://identity.example/jwks", Algorithms: []string{"RS256"},
		Skew: 30 * time.Second, MaxTokenBytes: 16 << 10, MaxJWKBodyBytes: 1 << 20,
		InitializationTimeout: 5 * time.Second, MinRefresh: time.Minute, MaxRefresh: time.Hour,
	}
	fmt.Println(settings.Validate(authjwt.SettingsPolicy{}))

	settings.AllowInsecureHTTP = true
	fmt.Println(settings.Validate(authjwt.SettingsPolicy{}))
	fmt.Println(settings.Validate(authjwt.SettingsPolicy{PermitInsecure: true}))
	// Output:
	// <nil>
	// authentication: invalid configuration: JWT remote settings AllowInsecureHTTP
	// <nil>
}

package laravelsanctum_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v3"
	authhttp "github.com/faustbrian/go-authentication/v3/adapters/http"
	"github.com/faustbrian/go-authentication/v3/adapters/laravelsanctum"
	"github.com/faustbrian/go-authentication/v3/bearer"
)

// The cases join the drifted Mono Track and Location parsers: both split at
// the first pipe, hash the remainder, and canonicalize leading zeros; Location's
// positive int64 bound is kept because Laravel token IDs are bigint keys.
func TestParseTokenSplitsAtFirstPipeAndCanonicalizesID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		token  string
		id     string
		secret string
	}{
		{token: "42|known-secret", id: "42", secret: "known-secret"},
		{token: "00042|known-secret", id: "42", secret: "known-secret"},
		{token: "1|secret|suffix", id: "1", secret: "secret|suffix"},
		{token: "9223372036854775807|secret", id: "9223372036854775807", secret: "secret"},
		{token: "1| ", id: "1", secret: " "},
	}
	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			t.Parallel()

			token, ok := laravelsanctum.ParseToken(tt.token)
			id, hasID := token.ID()
			if !ok || !hasID || id != tt.id || token.Digest() != sha256.Sum256([]byte(tt.secret)) {
				t.Fatalf("ParseToken(%q) = id %q/%v ok %v, want id %q and digest of %q", tt.token, id, hasID, ok, tt.id, tt.secret)
			}
		})
	}
}

func TestParseTokenHashesPipeFreeTokenWhole(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"plain-token", "x", "has space", "40"} {
		token, ok := laravelsanctum.ParseToken(value)
		id, hasID := token.ID()
		if !ok || hasID || id != "" || token.Digest() != sha256.Sum256([]byte(value)) {
			t.Fatalf("ParseToken(%q) = id %q/%v ok %v, want whole-token digest", value, id, hasID, ok)
		}
	}
}

func TestParseTokenRejectsMalformedLocators(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		"|secret",
		"0|secret",
		"0000|secret",
		"-1|secret",
		"+1|secret",
		" 1|secret",
		"1 |secret",
		"0x1|secret",
		"not-decimal|secret",
		"invalid|secret",
		"١|secret",
		"42|",
		"1|",
		"9223372036854775808|secret",
		"99999999999999999999999|secret",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			token, ok := laravelsanctum.ParseToken(value)
			if ok || token != (laravelsanctum.Token{}) {
				t.Fatalf("ParseToken(%q) accepted %#v", value, token)
			}
		})
	}
}

func TestTokenMatchesOnlyTheStoredRawDigest(t *testing.T) {
	t.Parallel()

	token, ok := laravelsanctum.ParseToken("7|secret")
	if !ok {
		t.Fatal("ParseToken() refused a valid token")
	}
	digest := sha256.Sum256([]byte("secret"))
	other := sha256.Sum256([]byte("other"))
	hexDigest := hex.EncodeToString(digest[:])
	for name, tt := range map[string]struct {
		stored []byte
		want   bool
	}{
		"raw digest":       {stored: digest[:], want: true},
		"other digest":     {stored: other[:], want: false},
		"hex text":         {stored: []byte(hexDigest), want: false},
		"short":            {stored: digest[:31], want: false},
		"long":             {stored: append(digest[:], 0), want: false},
		"nil":              {stored: nil, want: false},
		"whole-token hash": {stored: func() []byte { sum := sha256.Sum256([]byte("7|secret")); return sum[:] }(), want: false},
	} {
		if got := token.Matches(tt.stored); got != tt.want {
			t.Fatalf("%s: Matches() = %v, want %v", name, got, tt.want)
		}
	}
	if (laravelsanctum.Token{}).Matches(make([]byte, sha256.Size)) {
		t.Fatal("zero Token matched an all-zero digest")
	}
}

func TestTokenFormattingRedactsDigestAndID(t *testing.T) {
	t.Parallel()

	token, _ := laravelsanctum.ParseToken("1234567|private-secret")
	digest := token.Digest()
	for _, formatted := range []string{
		fmt.Sprint(token), fmt.Sprintf("%v", token), fmt.Sprintf("%+v", token), fmt.Sprintf("%#v", token), fmt.Sprintf("%s", token),
	} {
		if strings.Contains(formatted, "private") || strings.Contains(formatted, "1234567") ||
			strings.Contains(formatted, hex.EncodeToString(digest[:4])) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("formatted token = %q", formatted)
		}
	}
}

type recordingResolver struct {
	calls     int
	token     laravelsanctum.Token
	principal authentication.Principal
	err       error
}

func (r *recordingResolver) ResolveSanctumToken(_ context.Context, token laravelsanctum.Token) (authentication.Principal, error) {
	r.calls++
	r.token = token
	return r.principal, r.err
}

func bearerPrincipal(t *testing.T) authentication.Principal {
	t.Helper()
	principal, err := authentication.NewPrincipal(authentication.PrincipalSpec{Subject: "principal", Method: "bearer"})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func TestValidatorRejectsMalformedTokensWithoutResolving(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "0|secret", "x|secret", "42|", "9223372036854775808|secret"} {
		resolver := &recordingResolver{principal: bearerPrincipal(t)}
		validator, err := laravelsanctum.NewValidator(resolver)
		if err != nil {
			t.Fatal(err)
		}
		principal, err := validator.ValidateBearer(context.Background(), value)
		if !errors.Is(err, authentication.ErrCredentialsRejected) || !principal.IsAnonymous() || resolver.calls != 0 {
			t.Fatalf("ValidateBearer(%q) = %v, calls %d; want rejected without lookup", value, err, resolver.calls)
		}
	}
}

func TestValidatorPassesParsedTokenAndResolverOutcome(t *testing.T) {
	t.Parallel()

	want := bearerPrincipal(t)
	resolver := &recordingResolver{principal: want}
	validator, err := laravelsanctum.NewValidator(resolver)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := validator.ValidateBearer(context.Background(), "007|secret")
	id, _ := resolver.token.ID()
	if err != nil || principal.Subject() != "principal" || id != "7" || !resolver.token.Matches(digestOf("secret")) {
		t.Fatalf("ValidateBearer() = %v, %v; resolver saw id %q", principal.Subject(), err, id)
	}

	dependency := errors.New("store offline")
	resolver.err = dependency
	if _, err := validator.ValidateBearer(context.Background(), "plain"); !errors.Is(err, dependency) {
		t.Fatalf("resolver error = %v, want unchanged %v", err, dependency)
	}
}

func TestValidatorComposesWithBearerAuthenticatorAndPipeExtraction(t *testing.T) {
	t.Parallel()

	resolver := &recordingResolver{principal: bearerPrincipal(t)}
	validator, err := laravelsanctum.NewValidator(resolver)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := bearer.New(validator)
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := authhttp.NewExtractor(authhttp.BearerAuthorization(authhttp.WithBearerPipe()))
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Header: http.Header{"Authorization": {"Bearer 42|known-secret"}}, URL: &url.URL{}}
	credential, err := extractor.Extract(request)
	if err != nil {
		t.Fatal(err)
	}
	result, err := authenticator.Authenticate(context.Background(), credential)
	if _, authenticated := result.Principal(); err != nil || !authenticated {
		t.Fatalf("Authenticate() = %v", err)
	}

	resolver.err = errors.New("store offline")
	if _, err := authenticator.Authenticate(context.Background(), credential); !errors.Is(err, authentication.ErrAuthenticationUnavailable) {
		t.Fatalf("operational failure = %v, want unavailable", err)
	}
	resolver.err = authentication.NewFailure(authentication.FailureRejected)
	if _, err := authenticator.Authenticate(context.Background(), credential); !errors.Is(err, authentication.ErrCredentialsRejected) {
		t.Fatalf("unknown token = %v, want rejected", err)
	}
}

func TestNewValidatorRequiresResolver(t *testing.T) {
	t.Parallel()

	if _, err := laravelsanctum.NewValidator(nil); !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("NewValidator(nil) error = %v", err)
	}
	var function laravelsanctum.ResolverFunc
	if _, err := laravelsanctum.NewValidator(function); !errors.Is(err, authentication.ErrInvalidConfiguration) {
		t.Fatalf("NewValidator(nil func) error = %v", err)
	}
}

func FuzzParseToken(f *testing.F) {
	for _, seed := range []string{"", "1|a", "00|a", "1|", "|a", "a", "1|a|b", "9223372036854775807|a", "9223372036854775808|a"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		token, ok := laravelsanctum.ParseToken(value)
		if !ok {
			if token != (laravelsanctum.Token{}) {
				t.Fatal("refused token retained state")
			}
			return
		}
		id, hasID := token.ID()
		locator, secret, piped := strings.Cut(value, "|")
		if !piped {
			if hasID || token.Digest() != sha256.Sum256([]byte(value)) {
				t.Fatal("pipe-free token not hashed whole")
			}
			return
		}
		if !hasID || secret == "" || id == "" || id[0] == '0' || token.Digest() != sha256.Sum256([]byte(secret)) ||
			strings.TrimLeft(locator, "0") != id {
			t.Fatalf("pipe token parsed to id %q", id)
		}
	})
}

func digestOf(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

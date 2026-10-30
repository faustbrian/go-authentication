package authenticationhttp_test

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v3"
	authhttp "github.com/faustbrian/go-authentication/v3/adapters/http"
)

func requestWithHeader(header http.Header) *http.Request {
	return &http.Request{Header: header, URL: &url.URL{}}
}

func TestAPIKeySingleHeaderMatchesNameCaseInsensitivelyAndKeepsBytes(t *testing.T) {
	t.Parallel()

	extractor := mustExtractor(t, authhttp.APIKeySingleHeader("X-Shipit-Key"))
	for _, spelling := range []string{"X-SHIPIT-KEY", "X-Shipit-Key", "x-shipit-key"} {
		credential, err := extractor.Extract(requestWithHeader(http.Header{spelling: {"Private_fixture-123"}}))
		if err != nil {
			t.Fatalf("Extract(%s) error = %v", spelling, err)
		}
		apiKey, ok := credential.(authentication.APIKeyCredential)
		if !ok || apiKey.KeyID() != "" || apiKey.Key() != "Private_fixture-123" {
			t.Fatalf("Extract(%s) = %#v, want key-only credential with unchanged bytes", spelling, credential)
		}
	}
}

func TestAPIKeySingleHeaderRejectsAmbiguousAndMalformedValues(t *testing.T) {
	t.Parallel()

	extractor := mustExtractor(t, authhttp.APIKeySingleHeader("X-Shipit-Key", authhttp.WithAPIKeyMaxBytes(4096)))
	tests := []struct {
		name   string
		header http.Header
		want   error
	}{
		{name: "missing", header: http.Header{}, want: authentication.ErrCredentialsAbsent},
		{name: "empty", header: http.Header{"X-Shipit-Key": {""}}, want: authentication.ErrCredentialsInvalid},
		{name: "duplicate", header: http.Header{"X-Shipit-Key": {"fixture", "fixture"}}, want: authentication.ErrAmbiguousCredentials},
		{name: "different spelling", header: http.Header{"X-SHIPIT-KEY": {"fixture"}, "x-shipit-key": {"other"}}, want: authentication.ErrAmbiguousCredentials},
		{name: "joined", header: http.Header{"X-Shipit-Key": {"fixture,other"}}, want: authentication.ErrCredentialsInvalid},
		{name: "leading whitespace", header: http.Header{"X-Shipit-Key": {" fixture"}}, want: authentication.ErrCredentialsInvalid},
		{name: "inner space", header: http.Header{"X-Shipit-Key": {"fix ture"}}, want: authentication.ErrCredentialsInvalid},
		{name: "tab", header: http.Header{"X-Shipit-Key": {"fixture\t"}}, want: authentication.ErrCredentialsInvalid},
		{name: "control", header: http.Header{"X-Shipit-Key": {"fixture\r\nprivate"}}, want: authentication.ErrCredentialsInvalid},
		{name: "delete", header: http.Header{"X-Shipit-Key": {"fixture\x7f"}}, want: authentication.ErrCredentialsInvalid},
		{name: "unicode", header: http.Header{"X-Shipit-Key": {"fixture☃"}}, want: authentication.ErrCredentialsInvalid},
		{name: "oversized", header: http.Header{"X-Shipit-Key": {strings.Repeat("x", 4097)}}, want: authentication.ErrCredentialsInvalid},
		{name: "exact bound", header: http.Header{"X-Shipit-Key": {strings.Repeat("x", 4096)}}, want: nil},
		{name: "visible ASCII", header: http.Header{"X-Shipit-Key": {"!~\"#$%&'()*+-./:;<=>?@[\\]^_`{|}"}}, want: nil},
		{name: "authorization ignored by default", header: http.Header{"X-Shipit-Key": {"fixture"}, "Authorization": {"Bearer other"}}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			credential, err := extractor.Extract(requestWithHeader(tt.header))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Extract() error = %v, want %v", err, tt.want)
			}
			if err != nil && (credential != nil || strings.Contains(err.Error(), "fixture")) {
				t.Fatalf("failed extraction returned %#v or disclosed input: %v", credential, err)
			}
		})
	}
}

func TestAPIKeyRejectAuthorizationExcludesEveryAuthorizationField(t *testing.T) {
	t.Parallel()

	extractor := mustExtractor(t, authhttp.APIKeySingleHeader("X-Shipit-Key", authhttp.WithAPIKeyRejectAuthorization()))
	tests := []struct {
		name   string
		header http.Header
		want   error
	}{
		{name: "key alone", header: http.Header{"X-Shipit-Key": {"fixture"}}, want: nil},
		{name: "bearer beside key", header: http.Header{"X-Shipit-Key": {"fixture"}, "Authorization": {"Bearer other"}}, want: authentication.ErrAmbiguousCredentials},
		{name: "unknown scheme beside key", header: http.Header{"X-Shipit-Key": {"fixture"}, "Authorization": {"Custom other"}}, want: authentication.ErrAmbiguousCredentials},
		{name: "empty authorization beside key", header: http.Header{"X-Shipit-Key": {"fixture"}, "Authorization": {""}}, want: authentication.ErrAmbiguousCredentials},
		{name: "noncanonical authorization beside key", header: http.Header{"X-Shipit-Key": {"fixture"}, "authorization": {"Bearer other"}}, want: authentication.ErrAmbiguousCredentials},
		{name: "authorization alone", header: http.Header{"Authorization": {"Bearer other"}}, want: authentication.ErrCredentialsAbsent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := extractor.Extract(requestWithHeader(tt.header)); !errors.Is(err, tt.want) {
				t.Fatalf("Extract() error = %v, want %v", err, tt.want)
			}
		})
	}

	pair := mustExtractor(t, authhttp.APIKeyHeader("X-Key-Id", "X-Key", authhttp.WithAPIKeyRejectAuthorization()))
	header := http.Header{"X-Key-Id": {"id"}, "X-Key": {"key"}, "Authorization": {"Basic other"}}
	if _, err := pair.Extract(requestWithHeader(header)); !errors.Is(err, authentication.ErrAmbiguousCredentials) {
		t.Fatalf("pair with Authorization error = %v, want ambiguous", err)
	}
	delete(header, "Authorization")
	if _, err := pair.Extract(requestWithHeader(header)); err != nil {
		t.Fatalf("pair without Authorization error = %v", err)
	}
}

func TestAPIKeySingleHeaderComposesWithOtherSources(t *testing.T) {
	t.Parallel()

	extractor := mustExtractor(t, authhttp.APIKeySingleHeader("X-Api-Key"), authhttp.BearerAuthorization())
	both := http.Header{"X-Api-Key": {"key"}, "Authorization": {"Bearer token"}}
	if _, err := extractor.Extract(requestWithHeader(both)); !errors.Is(err, authentication.ErrAmbiguousCredentials) {
		t.Fatalf("two populated sources error = %v, want ambiguous", err)
	}
	credential, err := extractor.Extract(requestWithHeader(http.Header{"Authorization": {"Bearer token"}}))
	if err != nil || credential.Kind() != authentication.CredentialBearer {
		t.Fatalf("bearer-only Extract() = %v, %v", credential, err)
	}
}

func TestAPIKeySingleHeaderRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]authhttp.Source{
		"empty name":     authhttp.APIKeySingleHeader(""),
		"separator name": authhttp.APIKeySingleHeader("X Key"),
		"zero bound":     authhttp.APIKeySingleHeader("X-Key", authhttp.WithAPIKeyMaxBytes(0)),
		"negative bound": authhttp.APIKeySingleHeader("X-Key", authhttp.WithAPIKeyMaxBytes(-1)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := authhttp.NewExtractor(source); !errors.Is(err, authentication.ErrInvalidConfiguration) {
				t.Fatalf("NewExtractor() error = %v, want invalid configuration", err)
			}
		})
	}
}

func FuzzAPIKeySingleHeader(f *testing.F) {
	for _, value := range []string{"fixture", "", "a,b", " a", "\x00", "\x7f", strings.Repeat("x", 64), strings.Repeat("x", 65)} {
		f.Add(value)
	}
	extractor, err := authhttp.NewExtractor(authhttp.APIKeySingleHeader("X-Key", authhttp.WithAPIKeyMaxBytes(64)))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, value string) {
		credential, err := extractor.Extract(requestWithHeader(http.Header{"X-Key": {value}}))
		valid := value != "" && len(value) <= 64 && !strings.Contains(value, ",")
		for _, character := range []byte(value) {
			valid = valid && character > 0x20 && character < 0x7f
		}
		if valid {
			apiKey, ok := credential.(authentication.APIKeyCredential)
			if err != nil || !ok || apiKey.Key() != value || apiKey.KeyID() != "" {
				t.Fatalf("valid key changed or refused: %v", err)
			}
			return
		}
		if !errors.Is(err, authentication.ErrCredentialsInvalid) || credential != nil {
			t.Fatalf("invalid key accepted or misclassified: %v", err)
		}
	})
}

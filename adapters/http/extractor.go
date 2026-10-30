// Package authenticationhttp provides strict HTTP credential extraction, challenges,
// and authentication-only middleware for net/http. Start with NewExtractor and
// NewMiddleware; sources read borrowed request headers/cookies, never the
// URL query or body. Source byte bounds apply to selected values, not total
// header/cookie parsing allocations; server request limits remain
// deployment-owned.
// See docs/specification-decisions.md for RFC9110/7617/6750 parsing profiles.
package authenticationhttp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v3"
)

const (
	defaultMaxBasicBytes  = 8 * 1024
	defaultMaxBearerBytes = 8 * 1024
	defaultMaxKeyIDBytes  = 256
	defaultMaxAPIKeyBytes = 8 * 1024
)

// Source is an explicitly enabled HTTP credential location. Its private methods
// restrict implementations to this package; factory options are validated when
// passed to NewExtractor, not necessarily at factory invocation.
type Source interface {
	extract(*http.Request) (authentication.Credential, bool, error)
	validate() error
}

// Extractor rejects ambiguous credentials across all enabled sources.
type Extractor struct{ sources []Source }

// NewExtractor validates/copies one or more sources; there is no source-count
// cap. Built-in source configurations are immutable. Requests must not mutate
// concurrently with Extract; the extractor owns no request/body lifecycle.
func NewExtractor(sources ...Source) (*Extractor, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("%w: no HTTP credential sources", authentication.ErrInvalidConfiguration)
	}
	for _, source := range sources {
		if source == nil {
			return nil, fmt.Errorf("%w: nil HTTP credential source", authentication.ErrInvalidConfiguration)
		}
		if err := source.validate(); err != nil {
			return nil, err
		}
	}
	return &Extractor{sources: append([]Source(nil), sources...)}, nil
}

// Extract returns exactly one credential or a classified failure, evaluating
// enabled sources in order. Nil request fails invalid. The first source error
// takes precedence; otherwise multiple enabled credentials fail ambiguous. It
// does not mutate the request, honor its cancellation or normalize credentials.
func (e *Extractor) Extract(request *http.Request) (authentication.Credential, error) {
	if request == nil {
		return nil, authentication.NewFailure(authentication.FailureInvalid)
	}

	var found authentication.Credential
	for _, source := range e.sources {
		credential, present, err := source.extract(request)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		if found != nil {
			return nil, authentication.NewFailure(authentication.FailureAmbiguous)
		}
		found = credential
	}
	if found == nil {
		return nil, authentication.NewFailure(authentication.FailureAbsent)
	}
	return found, nil
}

type authorizationSource struct {
	kind     authentication.CredentialKind
	maxBytes int
	pipe     bool
}

// BasicAuthorization enables strict padded Base64 extraction with an inclusive
// 8 KiB decoded username/password total bound. Split at the first colon; empty
// password is representable, though Static rejects it. Bytes are not transcoded
// or normalized. AUTH-DEC-001/002 preserve scheme/encoding policy.
func BasicAuthorization() Source {
	return authorizationSource{kind: authentication.CredentialBasic, maxBytes: defaultMaxBasicBytes}
}

// BearerOption configures a bearer source.
type BearerOption func(*authorizationSource)

// WithBearerMaxBytes sets the inclusive bearer-token size bound.
func WithBearerMaxBytes(maximum int) BearerOption {
	return func(source *authorizationSource) { source.maxBytes = maximum }
}

// WithBearerPipe permits the pipe character in an opaque bearer credential.
//
// RFC 6750 bearer syntax rejects pipes by default. Enable this option only for
// an existing credential contract that uses a pipe-delimited opaque token.
func WithBearerPipe() BearerOption {
	return func(source *authorizationSource) { source.pipe = true }
}

// BearerAuthorization enables bearer extraction from the Authorization header.
func BearerAuthorization(options ...BearerOption) Source {
	source := authorizationSource{kind: authentication.CredentialBearer, maxBytes: defaultMaxBearerBytes}
	applyBearerOptions(&source, options)
	return source
}

func (s authorizationSource) validate() error {
	if (s.kind != authentication.CredentialBasic && s.kind != authentication.CredentialBearer) || s.maxBytes <= 0 {
		return fmt.Errorf("%w: Authorization source", authentication.ErrInvalidConfiguration)
	}
	return nil
}

func (s authorizationSource) extract(request *http.Request) (authentication.Credential, bool, error) {
	values := request.Header.Values("Authorization")
	if len(values) == 0 {
		return nil, false, nil
	}
	if len(values) != 1 {
		return nil, false, authentication.NewFailure(authentication.FailureAmbiguous)
	}

	wanted := "Basic"
	if s.kind == authentication.CredentialBearer {
		wanted = "Bearer"
	}
	separator := strings.IndexAny(values[0], " \t")
	if separator == -1 {
		if strings.EqualFold(values[0], wanted) {
			return nil, false, authentication.NewFailure(authentication.FailureInvalid)
		}
		return nil, false, nil
	}
	scheme := values[0][:separator]
	if !strings.EqualFold(scheme, wanted) {
		return nil, false, nil
	}
	payload := values[0][separator+1:]
	if values[0][separator] != ' ' || payload == "" || strings.ContainsAny(payload, " \t\r\n") {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}

	if s.kind == authentication.CredentialBearer {
		if len(payload) > s.maxBytes {
			return nil, false, authentication.NewFailure(authentication.FailureInvalid)
		}
		if !validBearerToken(payload, s.pipe) {
			return nil, false, authentication.NewFailure(authentication.FailureInvalid)
		}
		return authentication.NewBearerCredential(payload), true, nil
	}
	if len(payload) > base64.StdEncoding.EncodedLen(s.maxBytes) {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	if len(decoded) > s.maxBytes {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || username == "" || containsControl(username) || containsControl(password) {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	return authentication.NewBasicCredential(username, password), true, nil
}

func containsControl(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

type bearerNamedSource struct {
	location sourceLocation
	name     string
	maxBytes int
	pipe     bool
}

// BearerCookie explicitly enables bearer extraction from a cookie.
func BearerCookie(name string, options ...BearerOption) Source {
	configuration := authorizationSource{maxBytes: defaultMaxBearerBytes}
	applyBearerOptions(&configuration, options)
	return bearerNamedSource{
		location: locationCookie,
		name:     name,
		maxBytes: configuration.maxBytes,
		pipe:     configuration.pipe,
	}
}

func applyBearerOptions(source *authorizationSource, options []BearerOption) {
	for _, option := range options {
		if option != nil {
			option(source)
		}
	}
}

func (s bearerNamedSource) validate() error {
	if !validName(s.name) || s.maxBytes <= 0 || s.location != locationCookie {
		return fmt.Errorf("%w: bearer named source", authentication.ErrInvalidConfiguration)
	}
	return nil
}

func (s bearerNamedSource) extract(request *http.Request) (authentication.Credential, bool, error) {
	values, err := namedValues(request, s.location, s.name)
	if err != nil {
		return nil, false, err
	}
	if len(values) == 0 {
		return nil, false, nil
	}
	if len(values) != 1 {
		return nil, false, authentication.NewFailure(authentication.FailureAmbiguous)
	}
	if values[0] == "" {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	if len(values[0]) > s.maxBytes {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	if !validBearerToken(values[0], s.pipe) {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	return authentication.NewBearerCredential(values[0]), true, nil
}

// APIKeyOption configures an API-key source.
type APIKeyOption func(*apiKeySource)

// WithAPIKeyMaxBytes sets the inclusive API-key size bound.
func WithAPIKeyMaxBytes(maximum int) APIKeyOption {
	return func(source *apiKeySource) { source.maxKeyBytes = maximum }
}

// WithAPIKeyRejectAuthorization makes a present API key ambiguous when the
// request also carries any Authorization field, whatever its scheme or
// spelling. Authorization alone leaves the API-key source absent, so other
// enabled sources still apply.
func WithAPIKeyRejectAuthorization() APIKeyOption {
	return func(source *apiKeySource) { source.rejectAuthorization = true }
}

type apiKeySource struct {
	location            sourceLocation
	single              bool
	idName              string
	keyName             string
	maxIDBytes          int
	maxKeyBytes         int
	rejectAuthorization bool
}

// APIKeyHeader explicitly enables API-key extraction from two headers.
func APIKeyHeader(idHeader, keyHeader string, options ...APIKeyOption) Source {
	return newAPIKeySource(locationHeader, idHeader, keyHeader, options)
}

// APIKeySingleHeader explicitly enables key-only extraction from one header,
// producing an APIKeyCredential with an empty key ID. The name matches
// case-insensitively across every field spelling, and more than one value is
// ambiguous. The value must be non-empty visible ASCII without commas within the
// key byte bound (default 8 KiB); it is never trimmed or normalized. apikey.New
// and apikey.NewStatic require a key ID, so key-only credentials need a
// caller-owned Authenticator.
func APIKeySingleHeader(header string, options ...APIKeyOption) Source {
	source := newAPIKeySource(locationHeader, "", header, options)
	source.single = true
	return source
}

// APIKeyCookie explicitly enables API-key extraction from two cookies.
func APIKeyCookie(idCookie, keyCookie string, options ...APIKeyOption) Source {
	return newAPIKeySource(locationCookie, idCookie, keyCookie, options)
}

func newAPIKeySource(location sourceLocation, idName, keyName string, options []APIKeyOption) apiKeySource {
	source := apiKeySource{
		location: location,
		idName:   idName, keyName: keyName,
		maxIDBytes: defaultMaxKeyIDBytes, maxKeyBytes: defaultMaxAPIKeyBytes,
	}
	for _, option := range options {
		if option != nil {
			option(&source)
		}
	}
	return source
}

func (s apiKeySource) validate() error {
	if s.single {
		if !validName(s.keyName) || s.maxKeyBytes <= 0 || s.location != locationHeader {
			return fmt.Errorf("%w: API-key source", authentication.ErrInvalidConfiguration)
		}
		return nil
	}
	if !validName(s.idName) || !validName(s.keyName) || s.idName == s.keyName ||
		s.maxIDBytes <= 0 || s.maxKeyBytes <= 0 || s.location > locationCookie {
		return fmt.Errorf("%w: API-key source", authentication.ErrInvalidConfiguration)
	}
	return nil
}

func (s apiKeySource) extract(request *http.Request) (authentication.Credential, bool, error) {
	credential, present, err := s.extractKey(request)
	if err != nil || !present || !s.rejectAuthorization {
		return credential, present, err
	}
	if len(headerValuesFold(request.Header, "Authorization")) != 0 {
		return nil, false, authentication.NewFailure(authentication.FailureAmbiguous)
	}
	return credential, true, nil
}

func (s apiKeySource) extractKey(request *http.Request) (authentication.Credential, bool, error) {
	if s.single {
		return s.extractSingle(request)
	}
	ids, err := namedValues(request, s.location, s.idName)
	if err != nil {
		return nil, false, err
	}
	keys, err := namedValues(request, s.location, s.keyName)
	// The same request and location succeeded above, so this lookup cannot fail.
	_ = err
	if len(ids) == 0 && len(keys) == 0 {
		return nil, false, nil
	}
	if len(ids) != 1 || len(keys) != 1 {
		if len(ids) > 1 || len(keys) > 1 {
			return nil, false, authentication.NewFailure(authentication.FailureAmbiguous)
		}
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	if ids[0] == "" || keys[0] == "" {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	if len(ids[0]) > s.maxIDBytes || len(keys[0]) > s.maxKeyBytes {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	return authentication.NewAPIKeyCredential(ids[0], keys[0]), true, nil
}

// extractSingle scans every field spelling rather than the canonical key alone,
// so differently cased duplicates in a hand-built header map stay ambiguous.
func (s apiKeySource) extractSingle(request *http.Request) (authentication.Credential, bool, error) {
	values := headerValuesFold(request.Header, s.keyName)
	if len(values) == 0 {
		return nil, false, nil
	}
	if len(values) != 1 {
		return nil, false, authentication.NewFailure(authentication.FailureAmbiguous)
	}
	if !validSingleAPIKey(values[0], s.maxKeyBytes) {
		return nil, false, authentication.NewFailure(authentication.FailureInvalid)
	}
	return authentication.NewAPIKeyCredential("", values[0]), true, nil
}

// validSingleAPIKey admits RFC 9110 VCHAR octets except the comma, which
// separates combined field-line values and would make one key ambiguous.
func validSingleAPIKey(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character <= 0x20 || character >= 0x7f || character == ',' {
			return false
		}
	}
	return true
}

func headerValuesFold(header http.Header, name string) []string {
	var values []string
	for field, fieldValues := range header {
		if strings.EqualFold(field, name) {
			values = append(values, fieldValues...)
		}
	}
	return values
}

type sourceLocation uint8

const (
	locationHeader sourceLocation = iota
	locationCookie
)

// Cookies inspect the complete borrowed request fields before
// selected-value admission. Per-credential limits are not total parser budgets.
func namedValues(request *http.Request, location sourceLocation, name string) ([]string, error) {
	switch location {
	case locationHeader:
		return request.Header.Values(name), nil
	case locationCookie:
		var values []string
		for _, cookie := range request.Cookies() {
			if cookie.Name == name {
				values = append(values, cookie.Value)
			}
		}
		return values, nil
	default:
		return nil, authentication.NewFailure(authentication.FailureInvalid)
	}
}

func validBearerToken(token string, allowPipe bool) bool {
	padding := false
	for _, character := range []byte(token) {
		if character == '=' {
			padding = true
			continue
		}
		if padding ||
			(!isBearerCharacter(character) &&
				(!allowPipe || character != '|')) {
			return false
		}
	}
	return token != ""
}

func isBearerCharacter(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune("-._~+/", rune(character))
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range []byte(name) {
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(character)) {
			return false
		}
	}
	return true
}

var _ interface {
	Extract(*http.Request) (authentication.Credential, error)
} = (*Extractor)(nil)

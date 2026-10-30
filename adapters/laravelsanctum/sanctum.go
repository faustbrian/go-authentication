// Package laravelsanctum is a Laravel compatibility adapter for Sanctum
// personal access tokens presented as opaque bearer tokens. It parses the
// "id|secret" and pipe-free forms into a SHA-256 proof and validates through a
// caller-owned Resolver. It does not read storage, issue tokens, or authorize
// actions. Sanctum abilities are not enforced: the token only authenticates,
// so the adapter neither loads nor exposes them. Extract pipe-form tokens with
// authenticationhttp.BearerAuthorization(authenticationhttp.WithBearerPipe())
// and wrap the Validator with bearer.New. AUTH-DEC-014 records the profile.
package laravelsanctum

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v3"
	"github.com/faustbrian/go-authentication/v3/bearer"
)

// Token is a parsed personal access token. It retains the canonical token ID,
// when present, and the SHA-256 digest of the secret part, never the
// plaintext. Its formatted representation is redacted. The zero value is not a
// parsed token and matches no stored digest.
type Token struct {
	id     string
	digest [sha256.Size]byte
	parsed bool
}

// ParseToken follows Sanctum's PersonalAccessToken::findToken split. A token
// without a pipe is hashed whole and has no ID. Otherwise the text before the
// first pipe must be ASCII decimal for a positive signed 64-bit ID, leading
// zeros are dropped, and the non-empty remainder (which may contain pipes) is
// hashed. Empty or malformed tokens return the zero Token and false.
func ParseToken(token string) (Token, bool) {
	locator, secret, piped := strings.Cut(token, "|")
	if !piped {
		if token == "" {
			return Token{}, false
		}
		return Token{digest: sha256.Sum256([]byte(token)), parsed: true}, true
	}
	id, ok := canonicalID(locator)
	if !ok || secret == "" {
		return Token{}, false
	}
	return Token{id: id, digest: sha256.Sum256([]byte(secret)), parsed: true}, true
}

// canonicalID admits only digits so strconv's sign and base prefixes cannot
// reach the lookup; Sanctum IDs are positive bigint primary keys.
func canonicalID(locator string) (string, bool) {
	if locator == "" {
		return "", false
	}
	for _, character := range []byte(locator) {
		if character < '0' || character > '9' {
			return "", false
		}
	}
	id, err := strconv.ParseInt(locator, 10, 64)
	if err != nil || id <= 0 {
		return "", false
	}
	return strconv.FormatInt(id, 10), true
}

// ID returns the canonical decimal token ID and true for the "id|secret" form,
// or "" and false for a pipe-free token. Look the token up by ID when present,
// otherwise by Digest.
func (t Token) ID() (string, bool) { return t.id, t.id != "" }

// Digest returns the SHA-256 digest of the secret part, the value Sanctum
// stores hex-encoded in personal_access_tokens.token.
func (t Token) Digest() [sha256.Size]byte { return t.digest }

// Matches reports in constant time whether stored is exactly the raw 32-byte
// digest. Decode a hex column before comparing; any other length is false.
func (t Token) Matches(stored []byte) bool {
	return t.parsed && len(stored) == sha256.Size && subtle.ConstantTimeCompare(stored, t.digest[:]) == 1
}

// String returns fixed redacted prose.
func (Token) String() string { return "sanctum token [REDACTED]" }

// GoString returns a fixed redacted Go-syntax representation.
func (Token) GoString() string { return "laravelsanctum.Token{[REDACTED]}" }

// Format keeps every verb, including %+v, redacted.
func (t Token) Format(state fmt.State, verb rune) {
	if verb == 'v' && state.Flag('#') {
		_, _ = fmt.Fprint(state, t.GoString())
		return
	}
	_, _ = fmt.Fprint(state, t.String())
}

// Resolver looks up a parsed token in caller-owned storage. Implementations
// must compare the stored digest with Token.Matches when looking up by ID, and
// apply expiry, revocation and owner status. Return a Failure with
// FailureRejected for an unknown or refused token; bearer.New reports other
// errors as unavailable.
type Resolver interface {
	// ResolveSanctumToken borrows a non-nil context and a parsed token and
	// returns the token owner's principal with Method bearer.
	ResolveSanctumToken(context.Context, Token) (authentication.Principal, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(context.Context, Token) (authentication.Principal, error)

// ResolveSanctumToken directly invokes the function.
func (f ResolverFunc) ResolveSanctumToken(ctx context.Context, token Token) (authentication.Principal, error) {
	return f(ctx, token)
}

// Validator is a bearer.Validator for Sanctum personal access tokens.
type Validator struct{ resolver Resolver }

// NewValidator requires a resolver; a nil ResolverFunc is refused, other
// typed-nil resolvers are not detected.
func NewValidator(resolver Resolver) (*Validator, error) {
	if function, ok := resolver.(ResolverFunc); resolver == nil || (ok && function == nil) {
		return nil, fmt.Errorf("%w: Sanctum token resolver", authentication.ErrInvalidConfiguration)
	}
	return &Validator{resolver: resolver}, nil
}

// ValidateBearer parses the token and calls the resolver. A malformed token is
// rejected without a lookup, matching Sanctum, which finds no token for it.
// Resolver results and errors are returned unchanged.
func (v *Validator) ValidateBearer(ctx context.Context, token string) (authentication.Principal, error) {
	parsed, ok := ParseToken(token)
	if !ok {
		return authentication.Principal{}, authentication.NewFailure(authentication.FailureRejected)
	}
	return v.resolver.ResolveSanctumToken(ctx, parsed)
}

var _ bearer.Validator = (*Validator)(nil)

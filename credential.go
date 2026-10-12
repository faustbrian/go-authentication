package authentication

import "fmt"

// CredentialKind identifies a credential's protocol family.
type CredentialKind string

const (
	// CredentialBasic names Basic username/password credentials.
	CredentialBasic CredentialKind = "basic"
	// CredentialBearer names opaque bearer-token credentials.
	CredentialBearer CredentialKind = "bearer"
	// CredentialAPIKey names key-ID/key credentials.
	CredentialAPIKey CredentialKind = "api_key"
)

// Credential is a typed authentication credential. Implementations redact
// their secret-bearing representation.
type Credential interface {
	// Kind returns stable routing metadata without disclosing credential contents.
	// Custom implementations must keep String output redacted and any borrowed
	// state safe for concurrent use; the interface cannot enforce that obligation.
	Kind() CredentialKind
	fmt.Stringer
}

// BasicCredential is a username and password extracted from Basic
// authentication. Its formatted representation is always redacted.
type BasicCredential struct {
	username string
	password string
}

// NewBasicCredential retains raw strings without validation, normalization or
// cloning backing storage. Empty values are representable; extraction and
// authentication apply separate bounds. Strings cannot be securely erased here.
func NewBasicCredential(username, password string) BasicCredential {
	return BasicCredential{username: username, password: password}
}

// Kind returns CredentialBasic even for an empty zero-value credential.
func (BasicCredential) Kind() CredentialKind { return CredentialBasic }

// String returns fixed redacted prose without exposing stored values.
func (BasicCredential) String() string { return "basic credential [REDACTED]" }

// GoString returns a fixed redacted Go-syntax representation.
func (BasicCredential) GoString() string { return "authentication.BasicCredential{[REDACTED]}" }

// Username returns the raw username, which the application must classify for disclosure.
func (c BasicCredential) Username() string { return c.username }

// Password returns the plaintext password; never project it into logs or diagnostics.
func (c BasicCredential) Password() string { return c.password }

// BearerCredential is an opaque bearer token. Its formatted representation is
// always redacted.
type BearerCredential struct{ token string }

// NewBearerCredential retains the raw token without validation or cloning
// backing storage. Token bounds/grammar are separate consumer policies; secret
// accessors intentionally return plaintext and offer no secure-erasure guarantee.
func NewBearerCredential(token string) BearerCredential { return BearerCredential{token: token} }

// Kind returns CredentialBearer even for an empty zero-value credential.
func (BearerCredential) Kind() CredentialKind { return CredentialBearer }

// String returns fixed redacted prose without exposing stored values.
func (BearerCredential) String() string { return "bearer credential [REDACTED]" }

// GoString returns a fixed redacted Go-syntax representation.
func (BearerCredential) GoString() string { return "authentication.BearerCredential{[REDACTED]}" }

// Token returns the plaintext token; formatting redaction does not protect accessor use.
func (c BearerCredential) Token() string { return c.token }

// APIKeyCredential is an API key with an optional non-secret key identifier.
// Its formatted representation is always redacted.
type APIKeyCredential struct {
	keyID string
	key   string
}

// NewAPIKeyCredential retains raw ID/key strings without validation or backing-
// storage cloning. The ID is application-asserted non-secret; no confidentiality
// policy or secure-erasure lifecycle is enforced by this value.
func NewAPIKeyCredential(keyID, key string) APIKeyCredential {
	return APIKeyCredential{keyID: keyID, key: key}
}

// Kind returns CredentialAPIKey even for an empty zero-value credential.
func (APIKeyCredential) Kind() CredentialKind { return CredentialAPIKey }

// String returns fixed redacted prose without exposing stored values.
func (APIKeyCredential) String() string { return "api-key credential [REDACTED]" }

// GoString returns a fixed redacted Go-syntax representation.
func (APIKeyCredential) GoString() string { return "authentication.APIKeyCredential{[REDACTED]}" }

// KeyID returns the raw application-asserted non-secret key identifier.
func (c APIKeyCredential) KeyID() string { return c.keyID }

// Key returns the plaintext API key; never project it into logs or diagnostics.
func (c APIKeyCredential) Key() string { return c.key }

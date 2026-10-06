// Package apikey provides static and callback API-key authenticators.
package apikey

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"sync/atomic"

	authentication "github.com/faustbrian/go-authentication/v2"
)

// MaxEntries bounds active key candidates and per-request comparison work.
const MaxEntries = 256

// Entry configures one active key with a deterministic non-secret identifier.
type Entry struct {
	ID        string
	Key       string
	Principal authentication.PrincipalSpec
}

type staticEntry struct {
	id     [sha256.Size]byte
	key    [sha256.Size]byte
	result authentication.Result
}

type keySet struct{ entries []staticEntry }

// Static validates API keys against an atomically replaceable bounded key set.
type Static struct {
	digestKey [sha256.Size]byte
	keyOnce   sync.Once
	set       atomic.Pointer[keySet]
	limits    config
}

// NewStatic validates and copies the initial active key set with inclusive raw
// limits of 256 bytes per ID and 8 KiB per key. Principal limits are independent.
func NewStatic(entries []Entry) (*Static, error) {
	return NewStaticWithOptions(entries)
}

// NewStaticWithOptions validates and copies entries with immutable credential
// byte limits. WithMaxKeyIDBytes and WithMaxKeyBytes may reduce, but not exceed,
// the defaults of 256 bytes and 8 KiB. Zero or negative limits are invalid.
// Replace and Authenticate use the same limits for this owner's lifetime.
func NewStaticWithOptions(entries []Entry, options ...Option) (*Static, error) {
	configuration := config{maxKeyIDBytes: defaultMaxKeyIDBytes, maxKeyBytes: defaultMaxKeyBytes}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}
	if configuration.maxKeyIDBytes <= 0 || configuration.maxKeyIDBytes > defaultMaxKeyIDBytes ||
		configuration.maxKeyBytes <= 0 || configuration.maxKeyBytes > defaultMaxKeyBytes {
		return nil, fmt.Errorf("%w: API-key size bounds", authentication.ErrInvalidConfiguration)
	}
	authenticator := &Static{limits: configuration}
	if err := authenticator.Replace(entries); err != nil {
		return nil, err
	}
	return authenticator, nil
}

// Replace atomically replaces all active keys after validating the complete
// candidate set, admitting all credential bytes before hashing or copying
// principals. A failed replacement leaves the previous set and limits active.
// The zero-value Static uses the default limits and can install its first set.
func (s *Static) Replace(entries []Entry) error {
	digestKey := s.key()
	built, err := buildKeySet(entries, digestKey, s.byteLimits())
	if err != nil {
		return err
	}
	s.set.Store(built)
	return nil
}

// Authenticate admits raw ID/key bytes before hashing, then validates against a
// single immutable key-set snapshot. Oversized fields fail invalid; cancellation
// takes precedence.
func (s *Static) Authenticate(ctx context.Context, credential authentication.Credential) (authentication.Result, error) {
	if err := ctx.Err(); err != nil {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureUnavailable,
			authentication.WithFailureCause(err))
	}
	apiKey, ok := credential.(authentication.APIKeyCredential)
	if !ok || apiKey.KeyID() == "" || apiKey.Key() == "" {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureInvalid)
	}
	limits := s.byteLimits()
	if len(apiKey.KeyID()) > limits.maxKeyIDBytes || len(apiKey.Key()) > limits.maxKeyBytes {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureInvalid)
	}

	digestKey := s.key()
	id := secretDigest(digestKey, "id", apiKey.KeyID())
	key := secretDigest(digestKey, "key", apiKey.Key())
	matched := 0
	var result authentication.Result
	set := s.set.Load()
	if set == nil {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureUnavailable,
			authentication.WithFailureCause(authentication.ErrInvalidConfiguration))
	}
	for _, entry := range set.entries {
		current := subtle.ConstantTimeCompare(id[:], entry.id[:]) &
			subtle.ConstantTimeCompare(key[:], entry.key[:])
		if current == 1 {
			result = entry.result
		}
		matched |= current
	}
	if matched != 1 {
		return authentication.Result{}, authentication.NewFailure(authentication.FailureRejected)
	}

	return result, nil
}

func buildKeySet(entries []Entry, digestKey []byte, limits config) (*keySet, error) {
	if len(entries) == 0 || len(entries) > MaxEntries {
		return nil, fmt.Errorf("%w: API-key entry count", authentication.ErrInvalidConfiguration)
	}
	for index := range entries {
		if len(entries[index].ID) > limits.maxKeyIDBytes || len(entries[index].Key) > limits.maxKeyBytes {
			return nil, fmt.Errorf("%w: API-key credential size", authentication.ErrInvalidConfiguration)
		}
	}

	built := make([]staticEntry, 0, len(entries))
	ids := make(map[[sha256.Size]byte]struct{}, len(entries))
	keys := make(map[[sha256.Size]byte]struct{}, len(entries))
	for _, entry := range entries {
		if entry.ID == "" || entry.Key == "" {
			return nil, fmt.Errorf("%w: empty API-key data", authentication.ErrInvalidConfiguration)
		}
		if entry.Principal.Method != "" && entry.Principal.Method != "api_key" {
			return nil, fmt.Errorf("%w: API-key principal method", authentication.ErrInvalidConfiguration)
		}
		id := secretDigest(digestKey, "id", entry.ID)
		key := secretDigest(digestKey, "key", entry.Key)
		if _, exists := ids[id]; exists {
			return nil, fmt.Errorf("%w: duplicate API-key ID", authentication.ErrInvalidConfiguration)
		}
		if _, exists := keys[key]; exists {
			return nil, fmt.Errorf("%w: duplicate API key", authentication.ErrInvalidConfiguration)
		}
		ids[id] = struct{}{}
		keys[key] = struct{}{}

		spec := entry.Principal
		spec.Method = "api_key"
		principal, err := authentication.NewPrincipal(spec)
		if err != nil {
			return nil, fmt.Errorf("%w: API-key principal", authentication.ErrInvalidConfiguration)
		}
		// NewPrincipal guarantees this is a concrete identity.
		result, _ := authentication.NewAuthenticatedResult(principal)
		built = append(built, staticEntry{id: id, key: key, result: result})
	}

	return &keySet{entries: built}, nil
}

func (s *Static) byteLimits() config {
	limits := s.limits
	if limits.maxKeyIDBytes == 0 {
		limits.maxKeyIDBytes = defaultMaxKeyIDBytes
	}
	if limits.maxKeyBytes == 0 {
		limits.maxKeyBytes = defaultMaxKeyBytes
	}
	return limits
}

func (s *Static) key() []byte {
	s.keyOnce.Do(func() {
		copy(s.digestKey[:], rand.Text())
	})
	return s.digestKey[:]
}

func secretDigest(key []byte, domain, value string) [sha256.Size]byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(value))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

var _ authentication.Authenticator = (*Static)(nil)

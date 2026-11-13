package oidc

import (
	"context"
	"fmt"

	upstreamoidc "github.com/coreos/go-oidc/v3/oidc"
	authentication "github.com/faustbrian/go-authentication/v3"
)

const (
	googleAccountsIssuer       = "https://accounts.google.com"
	googleAccountsLegacyIssuer = "accounts.google.com"
)

// NewGoogleAccounts selects Google's documented ID-token issuer compatibility
// profile. Config.Issuer must be exactly https://accounts.google.com. Discovery,
// metadata issuer and key acquisition retain New's bounded HTTPS policy; the
// legacy form is accepted only in a fully validated, originally signed ID token.
// Both accepted token forms produce Principal.Issuer() equal to the canonical
// HTTPS issuer and preserve the exact subject, yielding one account namespace.
//
// All other Config semantics, claim/signature/nonce/hash checks, context/resource
// ownership and concurrency behavior are New's. No token bytes are rewritten,
// arbitrary aliases accepted, background work added or local session issued.
// Existing New and NewWithKeySet remain strictly byte-for-byte issuer matching.
func NewGoogleAccounts(ctx context.Context, configuration Config) (*Validator, error) {
	if configuration.Issuer != googleAccountsIssuer {
		return nil, fmt.Errorf("%w: Google Accounts issuer", authentication.ErrInvalidConfiguration)
	}
	validator, err := New(ctx, configuration)
	if err != nil {
		return nil, err
	}
	validator.googleAccounts = true
	return validator, nil
}

// NewGoogleAccountsWithKeySet selects NewGoogleAccounts' exact Google-only
// issuer policy using a caller-owned trusted key provider, with no discovery or
// network IO during construction. Config and key ownership/lifetime semantics
// are NewWithKeySet's; the key provider must perform real signature validation,
// honor context and support concurrency. The returned validator admits the two
// documented signed Google issuer forms into the same canonical identity.
func NewGoogleAccountsWithKeySet(configuration Config, keySet upstreamoidc.KeySet) (*Validator, error) {
	if configuration.Issuer != googleAccountsIssuer {
		return nil, fmt.Errorf("%w: Google Accounts issuer", authentication.ErrInvalidConfiguration)
	}
	validator, err := NewWithKeySet(configuration, keySet)
	if err != nil {
		return nil, err
	}
	validator.googleAccounts = true
	return validator, nil
}

package authentication

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// SignedReauthenticationRecord is the original completed credential-specific
// verification for one source session and protected action. The platform
// workflow, never a requester, owns creation and evidence signing after actual
// credential verification. Versions identify that original proof and credential.
// Signature is source-owned and must remain immutable during validation. Zero
// is invalid. This record neither issues a session nor consumes the proof.
type SignedReauthenticationRecord struct {
	// Issuer binds the trusted issuer, not a requester-selected authority.
	Issuer string
	// Environment separates otherwise identical issuer identities across deployment environments.
	Environment string
	// Proof binds the original credential-specific verification to session, action and freshness.
	Proof ReauthenticationProof
	// ProofVersion is the positive version of the original completed authentication proof.
	ProofVersion uint64
	// CredentialID identifies the exact credential that completed verification.
	CredentialID string
	// CredentialVersion is the positive version of that authenticating credential.
	CredentialVersion uint64
	// KeyID selects an explicitly configured trusted evidence key, not an arbitrary remote key.
	KeyID string
	// Signature is source-owned Ed25519 evidence and must not change during validation.
	Signature []byte
}

// ReauthenticationSource optionally extends AuthoritySource with an exact
// original proof lookup. Implementations own durable signing custody, bound IO
// and decoding, honor cancellation and support concurrent calls. They must not
// manufacture completed verification from a caller's projection. Current
// credential/session checks and atomic one-use reservation remain the protected
// transaction's responsibility. Existing AuthoritySource implementations need
// not implement this interface; their reauthentication validation fails closed.
type ReauthenticationSource interface {
	// Reauthentication retrieves original completed credential verification by exact proof identity.
	Reauthentication(context.Context, ProofID) (SignedReauthenticationRecord, error)
}

// Format redacts correlated identities and evidence signatures for every verb.
func (SignedReauthenticationRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "authentication.SignedReauthenticationRecord(redacted)")
}

// SigningBytes returns the bounded v1 domain-separated original verification
// frame, excluding Signature. UTC normalization preserves instants. This uses
// configured evidence keys, not an access-token signature or signin frame.
// Malformed input returns only ErrInvalidProof. It grants no authority itself.
func (r SignedReauthenticationRecord) SigningBytes() ([]byte, error) {
	p := r.Proof
	use := ReauthenticationUse{ProofUse: ProofUse{Tenant: p.Proof.Tenant, Subject: p.Proof.Subject, Purpose: p.Proof.Purpose, Audience: p.Proof.Audience, Now: p.Proof.IssuedAt}, SessionID: p.SessionID, SessionVersion: p.SessionVersion, Action: p.Action, MaximumAge: 24 * time.Hour}
	if !identifier(r.Issuer) || !identifier(r.Environment) || p.Validate(use) != nil || r.ProofVersion == 0 || !identifier(r.CredentialID) || r.CredentialVersion == 0 || !canonicalASCII(r.KeyID, 1, 128) {
		return nil, ErrInvalidProof
	}
	r.Signature = nil
	r.Proof.Proof.IssuedAt = p.Proof.IssuedAt.UTC()
	r.Proof.Proof.ExpiresAt = p.Proof.ExpiresAt.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return nil, ErrInvalidProof
	}
	return append([]byte("golib/shared-issuer-v1/reauthentication\x00"), b...), nil
}

// ValidateReauthenticationProof establishes signed-original provenance for the
// existing ReauthenticationProof type; its structural Validate method alone
// does not authenticate. Exact session/version/action, tenant/subject/purpose,
// audience and exclusive freshness are checked against this authority's clock,
// ignoring use.ProofUse.Now. The bounded source read cannot reset timestamps.
// Zero/legacy compositions deny. Dependency failure or panic is unavailable;
// signature/scope/freshness failures retain stable proof errors. Cancellation
// retains its context error. This owns no background resources and performs no
// session issuance, current-authority refresh, rate limiting or consumption:
// owning workflows and protected transactions must provide those effects.
func (a *AuthorityAuthenticator) ValidateReauthenticationProof(ctx context.Context, p ReauthenticationProof, use ReauthenticationUse) (err error) {
	defer func() {
		if recover() != nil {
			err = NewFailure(FailureUnavailable)
		}
	}()
	if a == nil || a.capability == nil || ctx == nil {
		return ErrInvalidProof
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	source, ok := a.source.(ReauthenticationSource)
	if !ok {
		return ErrInvalidConfiguration
	}
	if use.ProofUse.Audience != a.audience {
		return ErrProofAudienceMismatch
	}
	if use.MaximumAge <= 0 {
		return ErrInvalidProof
	}
	started := a.clock.Now()
	use.ProofUse.Now = started
	if err := p.Validate(use); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, a.readTimeout)
	defer cancel()
	r, err := source.Reauthentication(bounded, p.Proof.ID)
	now := a.clock.Now()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || bounded.Err() != nil || now.Before(started) || now.Sub(started) > a.readTimeout {
		return NewFailure(FailureUnavailable)
	}
	frame, err := r.SigningBytes()
	if err != nil {
		return ErrInvalidProof
	}
	key := a.evidenceKeys[r.KeyID]
	if len(key) != ed25519.PublicKeySize || len(r.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, frame, r.Signature) || r.Issuer != a.issuer || r.Environment != a.environment || !equalProof(r.Proof.Proof, p.Proof) || r.Proof.SessionID != p.SessionID || r.Proof.SessionVersion != p.SessionVersion || r.Proof.Action != p.Action {
		return ErrInvalidProof
	}
	use.ProofUse.Now = now
	return p.Validate(use)
}

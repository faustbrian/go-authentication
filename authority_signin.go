package authentication

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SignedSignInRecord is the bounded original outcome of completed authentication,
// including the exact proof and authenticating credential versions. Challenge,
// rejected and anonymous states are not final authentication. Only the authority
// that completed verification may sign it; signing requester-supplied metadata
// or account existence violates this contract. Zero is invalid. The source owns
// Signature and must not mutate a returned record while validation runs.
type SignedSignInRecord struct {
	// Issuer binds the trusted issuer, not a requester-selected authority.
	Issuer string
	// Environment separates otherwise identical issuer identities across deployment environments.
	Environment string
	// State must be SignInStateAuthenticated; anonymous, challenge and rejected outcomes cannot mint proofs.
	State SignInState
	// Proof is the exact original successful session-issue proof.
	Proof Proof
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

// SignInSource optionally extends AuthoritySource with lookup of completed
// signins by exact ProofID, never by requester-created claims. Its implementation
// owns durable original records and signing custody, honors bounded cancellation,
// bounds decoding before allocation and supports concurrent calls. It neither
// consumes a proof nor commits a session. Existing AuthoritySource implementations
// need not implement it; those compositions cannot issue AuthenticatedProof.
type SignInSource interface {
	// SignInAuthentication retrieves the original successful signin, not requester-created claims.
	SignInAuthentication(context.Context, ProofID) (SignedSignInRecord, error)
}

// AuthenticatedProofSpec exposes a bounded caller-owned projection for trusted
// persistence. It is not authority and cannot construct an AuthenticatedProof.
// Versions bind the original proof and exact credential, not a global counter.
type AuthenticatedProofSpec struct {
	// Proof retains the complete original structural proof binding; it is not sufficient authority by itself.
	Proof Proof
	// ProofVersion is the positive version of the original completed authentication proof.
	ProofVersion uint64
	// CredentialID identifies the exact credential that completed verification.
	CredentialID string
	// CredentialVersion is the positive version of that authenticating credential.
	CredentialVersion uint64
}

// AuthenticatedProof is an immutable final-authentication result issued by one
// configured AuthorityAuthenticator. Zero is invalid; copies are safe concurrently
// and own no resources. Only that expected instance's ValidateAuthenticatedProof
// establishes provenance. This is not session authority, revocation evidence or
// one-time consumption; the protected transaction must recheck current versions
// and atomically consume the original proof with its session effects.
type AuthenticatedProof struct{ state *authenticatedProofState }
type authenticatedProofState struct {
	bindings   AuthenticatedProofSpec
	capability *mintingCapability
}

// AuthenticatedProofIssuer is the final-proof boundary, not an authentication
// workflow. Implementing it grants no private minting capability. Its method
// reads signed original authentication by ID and conserves original timestamps.
type AuthenticatedProofIssuer interface {
	// IssueAuthenticatedProof authenticates the signed original signin before minting instance-bound proof.
	IssueAuthenticatedProof(context.Context, Proof) (AuthenticatedProof, error)
}

// Bindings returns a scalar projection, never transferable minting authority.
// Zero returns zero. Correlated identifiers must not be logged.
func (p AuthenticatedProof) Bindings() AuthenticatedProofSpec {
	if p.state == nil {
		return AuthenticatedProofSpec{}
	}
	return p.state.bindings
}

// Format redacts correlated authentication data for every formatting verb.
func (AuthenticatedProof) Format(s fmt.State, _ rune) {
	io.WriteString(s, "authentication.AuthenticatedProof(redacted)")
}

// MarshalJSON denies accidental final-proof encoding. Use Bindings only within
// explicitly trusted persistence; that projection cannot replace provenance.
func (AuthenticatedProof) MarshalJSON() ([]byte, error) { return nil, ErrInvalidProof }

// MarshalText denies implicit text and map-key disclosure.
func (AuthenticatedProof) MarshalText() ([]byte, error) { return nil, ErrInvalidProof }

// Format redacts original records and their signature from diagnostics.
func (SignedSignInRecord) Format(s fmt.State, _ rune) {
	io.WriteString(s, "authentication.SignedSignInRecord(redacted)")
}

// SigningBytes returns the v1 domain-separated original successful-signin frame,
// excluding Signature. It preserves the original proof, exact versions and
// credential; UTC normalization changes no instant. It cannot grant authority.
// Bounds are validated before allocation. Invalid input returns ErrInvalidProof.
// Signatures must use a configured evidence key; permanent-upgrade and access
// token framing are distinct and unchanged.
func (r SignedSignInRecord) SigningBytes() ([]byte, error) {
	if !identifier(r.Issuer) || !identifier(r.Environment) || r.State != SignInStateAuthenticated || !r.Proof.valid() || r.Proof.Purpose != "session-issue" || r.ProofVersion == 0 || !identifier(r.CredentialID) || r.CredentialVersion == 0 || !canonicalASCII(r.KeyID, 1, 128) {
		return nil, ErrInvalidProof
	}
	r.Signature = nil
	r.Proof.IssuedAt = r.Proof.IssuedAt.UTC()
	r.Proof.ExpiresAt = r.Proof.ExpiresAt.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return nil, ErrInvalidProof
	}
	return append([]byte("golib/shared-issuer-v1/signin-authentication\x00"), b...), nil
}

// AuthenticatedProofIssuerFromAuthenticator accepts only the package-owned
// trusted authority with its private minting identity and optional SignInSource.
// External implementations and legacy compositions without that source fail
// closed with ErrInvalidConfiguration. No authentication or source read occurs.
func AuthenticatedProofIssuerFromAuthenticator(a Authenticator) (AuthenticatedProofIssuer, error) {
	authority, ok := a.(*AuthorityAuthenticator)
	if !ok || authority == nil || authority.capability == nil {
		return nil, ErrInvalidConfiguration
	}
	source, ok := authority.source.(SignInSource)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	return &authenticatedProofIssuer{authority: authority, source: source}, nil
}

type authenticatedProofIssuer struct {
	authority *AuthorityAuthenticator
	source    SignInSource
}

func (i *authenticatedProofIssuer) IssueAuthenticatedProof(ctx context.Context, requested Proof) (AuthenticatedProof, error) {
	a := i.authority
	if ctx == nil || ctx.Err() != nil {
		return AuthenticatedProof{}, NewFailure(FailureUnavailable)
	}
	use := ProofUse{Tenant: requested.Tenant, Subject: requested.Subject, Purpose: "session-issue", Audience: a.audience, Now: a.clock.Now()}
	if err := requested.Validate(use); err != nil {
		return AuthenticatedProof{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, a.readTimeout)
	defer cancel()
	started := a.clock.Now()
	record, err := i.source.SignInAuthentication(bounded, requested.ID)
	now := a.clock.Now()
	if err != nil || bounded.Err() != nil || now.Before(started) || now.Sub(started) > a.readTimeout {
		return AuthenticatedProof{}, NewFailure(FailureUnavailable)
	}
	b, err := record.SigningBytes()
	if err != nil {
		return AuthenticatedProof{}, ErrInvalidProof
	}
	key := a.evidenceKeys[record.KeyID]
	if key == nil || len(record.Signature) != ed25519.SignatureSize || !ed25519.Verify(key, b, record.Signature) || record.Issuer != a.issuer || record.Environment != a.environment || !equalProof(record.Proof, requested) {
		return AuthenticatedProof{}, ErrInvalidProof
	}
	use.Now = now
	if err := record.Proof.Validate(use); err != nil {
		return AuthenticatedProof{}, err
	}
	proof, _ := NewProof(ProofSpec(record.Proof))
	return AuthenticatedProof{state: &authenticatedProofState{bindings: AuthenticatedProofSpec{Proof: proof, ProofVersion: record.ProofVersion, CredentialID: strings.Clone(record.CredentialID), CredentialVersion: record.CredentialVersion}, capability: a.capability}}, nil
}

// ValidateAuthenticatedProof checks minting identity against THIS configured
// authority, then exact tenant/subject/session-issue purpose/audience and
// exclusive expiry at the trusted caller's now. A foreign composition with
// identical keys cannot substitute provenance. It performs no IO and grants no
// one-time use or current lifecycle validity; consuming adapters own those checks.
func (a *AuthorityAuthenticator) ValidateAuthenticatedProof(p AuthenticatedProof, use ProofUse) error {
	if a == nil || a.capability == nil || p.state == nil || p.state.capability != a.capability {
		return ErrInvalidProof
	}
	if use.Purpose != "session-issue" {
		return ErrProofPurposeMismatch
	}
	return p.state.bindings.Proof.Validate(use)
}

package authentication

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	// ErrInvalidProof identifies malformed, incomplete or mismatched proof data.
	ErrInvalidProof = errors.New("authentication: invalid proof")
	// ErrExpiredProof identifies a proof used at or after its exclusive expiry.
	ErrExpiredProof = errors.New("authentication: expired proof")
	// ErrProofAudienceMismatch identifies use at a different audience.
	ErrProofAudienceMismatch = errors.New("authentication: proof audience mismatch")
	// ErrProofPurposeMismatch identifies use for a different protected operation.
	ErrProofPurposeMismatch = errors.New("authentication: proof purpose mismatch")
)

// Assurance is a closed authentication-strength classification. Its zero value
// is invalid for successful authentication. Compare strength using AtLeast.
type Assurance uint8

const (
	// AssuranceUnspecified is invalid for successful authentication.
	AssuranceUnspecified Assurance = iota
	// AssuranceSingleFactor records one successfully verified factor.
	AssuranceSingleFactor
	// AssuranceMultiFactor records successful independent multiple-factor verification.
	AssuranceMultiFactor
	// AssurancePhishingResistant records a verified phishing-resistant authentication method.
	AssurancePhishingResistant
)

// AtLeast compares valid assurance levels; unspecified and unknown values
// never satisfy a requirement, including another invalid requirement.
func (a Assurance) AtLeast(required Assurance) bool {
	return a.valid() && required.valid() && a >= required
}

func (a Assurance) valid() bool {
	return a == AssuranceSingleFactor || a == AssuranceMultiFactor || a == AssurancePhishingResistant
}

// OneTimeCode is an immutable secret constructed only by NewOneTimeCode. Its
// zero value is invalid. It exposes no conversion, marshaling, logging or
// formatting method. Release every copy immediately after terminal use.
// Concurrent copying is safe; retaining a copy retains the secret.
type OneTimeCode struct{ secret func() string }

// RecoveryCode is an immutable secret constructed only by NewRecoveryCode. Its
// zero value is invalid. It exposes no secret accessor or serialization method.
// Atomic single-use verification is owned by the consuming credential store.
// Release every copy after terminal use; concurrent copying is safe.
type RecoveryCode struct{ secret func() string }

// NewOneTimeCode copies 4..128 visible ASCII symbols into private immutable
// storage. Invalid inputs return only ErrInvalidProof, never the input.
func NewOneTimeCode(value string) (OneTimeCode, error) {
	if !canonicalASCII(value, 4, 128) {
		return OneTimeCode{}, ErrInvalidProof
	}
	// A closure keeps the representation opaque even to recursive fmt verbs,
	// which otherwise display unexported string fields without calling methods.
	copy := strings.Clone(value)
	return OneTimeCode{secret: func() string { return copy }}, nil
}

// NewRecoveryCode copies 8..256 visible canonical ASCII symbols into private
// immutable storage. Invalid inputs return only ErrInvalidProof.
func NewRecoveryCode(value string) (RecoveryCode, error) {
	if !canonicalASCII(value, 8, 256) {
		return RecoveryCode{}, ErrInvalidProof
	}
	copy := strings.Clone(value)
	return RecoveryCode{secret: func() string { return copy }}, nil
}

// ProofID is a non-secret proof identity of 22..128 visible ASCII bytes.
// Equality is meaningful only within one authentication authority. The zero
// value is invalid; NewProof validates it as part of the complete binding.
type ProofID string

// Purpose names one exact protected operation, never a wildcard or hierarchy.
// The zero value is invalid. NewPurpose constructs a validated value.
type Purpose string

// NewPurpose copies a purpose of 1..128 visible canonical ASCII bytes.
func NewPurpose(value string) (Purpose, error) {
	if !canonicalASCII(value, 1, 128) {
		return "", ErrInvalidProof
	}
	return Purpose(strings.Clone(value)), nil
}

// Proof binds an identity and operation until exclusive expiry. Its zero value
// is invalid. This non-secret projection is caller-owned: callers must not
// mutate a shared instance concurrently. Validate rechecks even literal values;
// construction alone does not establish authentication authority.
type Proof struct {
	// ID identifies this exact proof or versioned authority node within its owning issuer.
	ID ProofID
	// Tenant binds the exact selected tenant; it is not inferred from the calling workload.
	Tenant string
	// Subject binds the exact authenticated subject, not an authorization decision.
	Subject string
	// Method identifies the method that established authentication.
	Method string
	// Assurance records the established closed authentication-strength classification.
	Assurance Assurance
	// Purpose binds one exact protected operation, never a wildcard.
	Purpose Purpose
	// Audience binds the exact intended verifier or consuming service.
	Audience string
	// IssuedAt retains the original issuance time; copying cannot refresh it.
	IssuedAt time.Time
	// ExpiresAt is the exclusive original proof expiry, at most twenty-four hours after IssuedAt.
	ExpiresAt time.Time
}

// ProofSpec is caller-owned construction input with the same bounds as Proof.
// NewProof copies retained strings; time values are immutable value copies.
type ProofSpec struct {
	// ID identifies this exact proof or versioned authority node within its owning issuer.
	ID ProofID
	// Tenant binds the exact selected tenant; it is not inferred from the calling workload.
	Tenant string
	// Subject binds the exact authenticated subject, not an authorization decision.
	Subject string
	// Method identifies the method that established authentication.
	Method string
	// Assurance records the established closed authentication-strength classification.
	Assurance Assurance
	// Purpose binds one exact protected operation, never a wildcard.
	Purpose Purpose
	// Audience binds the exact intended verifier or consuming service.
	Audience string
	// IssuedAt retains the original issuance time; copying cannot refresh it.
	IssuedAt time.Time
	// ExpiresAt is the exclusive original proof expiry, at most twenty-four hours after IssuedAt.
	ExpiresAt time.Time
}

// ProofUse is a complete exact use binding. Now must come from the trusted
// caller-owned clock, not credential input. Zero-valued fields are invalid.
type ProofUse struct {
	// Tenant binds the exact selected tenant; it is not inferred from the calling workload.
	Tenant string
	// Subject binds the exact authenticated subject, not an authorization decision.
	Subject string
	// Purpose binds one exact protected operation, never a wildcard.
	Purpose Purpose
	// Audience binds the exact intended verifier or consuming service.
	Audience string
	// Now comes from the trusted caller clock, not request-controlled metadata.
	Now time.Time
}

// NewProof validates and copies every binding. Identity fields are 1..256
// valid UTF-8 bytes without controls; identity/purpose have tighter ASCII bounds.
// Issuance precedes expiry and lifetime is at most 24 hours. No authority is
// inferred from the existence of identifiers in this non-secret projection.
func NewProof(spec ProofSpec) (Proof, error) {
	proof := Proof(spec)
	if !proof.valid() {
		return Proof{}, ErrInvalidProof
	}
	proof.ID = ProofID(strings.Clone(string(spec.ID)))
	proof.Tenant = strings.Clone(spec.Tenant)
	proof.Subject = strings.Clone(spec.Subject)
	proof.Method = strings.Clone(spec.Method)
	proof.Purpose = Purpose(strings.Clone(string(spec.Purpose)))
	proof.Audience = strings.Clone(spec.Audience)
	return proof, nil
}

func (p Proof) valid() bool {
	return canonicalASCII(string(p.ID), 22, 128) && canonicalASCII(string(p.Purpose), 1, 128) &&
		identifier(p.Tenant) && identifier(p.Subject) && identifier(p.Method) && identifier(p.Audience) &&
		p.Assurance.valid() && !p.IssuedAt.IsZero() && !p.ExpiresAt.IsZero() &&
		p.IssuedAt.Before(p.ExpiresAt) && p.ExpiresAt.Sub(p.IssuedAt) <= 24*time.Hour
}

// Validate rechecks structure and binds exact tenant, subject, purpose and
// audience. Expiry is exclusive and future-issued proofs fail closed. Errors
// are stable, redacted sentinels; no input is included. Concurrent validation
// of an unmodified proof and use is safe and owns no resources.
func (p Proof) Validate(use ProofUse) error {
	if !p.valid() || !identifier(use.Tenant) || !identifier(use.Subject) || !identifier(use.Audience) ||
		!canonicalASCII(string(use.Purpose), 1, 128) || use.Now.IsZero() || use.Now.Before(p.IssuedAt) {
		return ErrInvalidProof
	}
	if !use.Now.Before(p.ExpiresAt) {
		return ErrExpiredProof
	}
	if p.Tenant != use.Tenant || p.Subject != use.Subject {
		return ErrInvalidProof
	}
	if p.Purpose != use.Purpose {
		return ErrProofPurposeMismatch
	}
	if p.Audience != use.Audience {
		return ErrProofAudienceMismatch
	}
	return nil
}

// ReauthenticationProof binds a proof to exactly one session version and
// protected action. Its zero value is invalid. Session and action are 1..128
// visible ASCII bytes. It is non-secret caller-owned data, not a new session.
type ReauthenticationProof struct {
	// Proof retains the complete original structural proof binding; it is not sufficient authority by itself.
	Proof Proof
	// SessionID identifies the exact source session for reauthentication.
	SessionID string
	// SessionVersion is the positive source-session version that must remain current.
	SessionVersion uint64
	// Action binds the exact protected action requiring reauthentication.
	Action string
}

// ReauthenticationUse binds the current session/action and positive maximum
// proof age (at most 24 hours). Clock ownership follows ProofUse.
type ReauthenticationUse struct {
	// ProofUse supplies the exact tenant, subject, purpose, audience and trusted clock binding.
	ProofUse ProofUse
	// SessionID identifies the exact source session for reauthentication.
	SessionID string
	// SessionVersion is the positive source-session version that must remain current.
	SessionVersion uint64
	// Action binds the exact protected action requiring reauthentication.
	Action string
	// MaximumAge is the positive exclusive proof-age bound, at most twenty-four hours.
	MaximumAge time.Duration
}

// Validate requires exact current session/version/action plus ProofUse.
// It fails closed at the freshness boundary; it owns no resources and is safe
// for concurrent calls on values that are not concurrently modified.
func (p ReauthenticationProof) Validate(use ReauthenticationUse) error {
	if err := p.Proof.Validate(use.ProofUse); err != nil {
		return err
	}
	if !canonicalASCII(p.SessionID, 1, 128) || !canonicalASCII(p.Action, 1, 128) || p.SessionVersion == 0 ||
		p.SessionID != use.SessionID || p.SessionVersion != use.SessionVersion || p.Action != use.Action ||
		use.MaximumAge > 24*time.Hour || use.ProofUse.Now.Sub(p.Proof.IssuedAt) >= use.MaximumAge {
		return ErrInvalidProof
	}
	return nil
}

// ProofKind is a closed discriminator; its zero and unknown values are invalid.
type ProofKind uint8

const (
	// ProofKindUnspecified is an invalid proof-arm selection.
	ProofKindUnspecified ProofKind = iota
	// ProofKindReauthentication selects the exact session/action-bound reauthentication arm.
	ProofKindReauthentication
	// ProofKindRecovery selects recovery only when the consuming operation explicitly allows it.
	ProofKindRecovery
)

// ReauthenticationOrRecoveryProof requires exactly its selected arm. Its zero
// value is invalid. The unselected arm must be entirely zero, not merely invalid.
// Recovery is accepted only under an explicit consuming-operation allowance.
type ReauthenticationOrRecoveryProof struct {
	// Kind selects the closed classification; unknown and zero values are invalid.
	Kind ProofKind
	// Reauthentication is populated only when Kind selects reauthentication.
	Reauthentication ReauthenticationProof
	// Recovery is populated only when Kind selects explicitly allowed recovery.
	Recovery Proof
}

// Validate enforces the closed union and operation's explicit recovery policy.
// The recovery arm uses the exact ProofUse; the reauthentication arm additionally
// checks session freshness and action. It owns no resources.
func (p ReauthenticationOrRecoveryProof) Validate(use ReauthenticationUse, allowRecovery bool) error {
	switch p.Kind {
	case ProofKindReauthentication:
		if p.Recovery != (Proof{}) {
			return ErrInvalidProof
		}
		return p.Reauthentication.Validate(use)
	case ProofKindRecovery:
		if !allowRecovery || p.Reauthentication != (ReauthenticationProof{}) {
			return ErrInvalidProof
		}
		return p.Recovery.Validate(use.ProofUse)
	default:
		return ErrInvalidProof
	}
}

// RecoveryPath is a closed recovery-channel selection. The zero value is
// invalid; consumers must retain the selected path with the issued challenge.
type RecoveryPath uint8

const (
	// RecoveryPathUnspecified is an invalid recovery-channel selection.
	RecoveryPathUnspecified RecoveryPath = iota
	// RecoveryPathEmail selects policy-approved verified email recovery.
	RecoveryPathEmail
	// RecoveryPathPhone selects policy-approved verified phone recovery.
	RecoveryPathPhone
	// RecoveryPathPasskey selects policy-approved passkey recovery.
	RecoveryPathPasskey
	// RecoveryPathAdministrator selects independently authorized administrative recovery.
	RecoveryPathAdministrator
)

// Valid reports whether the path is one of the supported explicit channels.
func (p RecoveryPath) Valid() bool {
	return p == RecoveryPathEmail || p == RecoveryPathPhone || p == RecoveryPathPasskey || p == RecoveryPathAdministrator
}

// SignInState is a closed sign-in outcome classification. The zero value is
// invalid; state-specific result arms are owned by identity consumers.
type SignInState uint8

const (
	// SignInStateUnspecified is an invalid signin result.
	SignInStateUnspecified SignInState = iota
	// SignInStateAuthenticated records completed successful authentication.
	SignInStateAuthenticated
	// SignInStateChallengeRequired requires an additional challenge before authentication is complete.
	SignInStateChallengeRequired
	// SignInStateRejected records a refused authentication attempt.
	SignInStateRejected
)

// Valid reports whether the state is a supported terminal or challenge state.
func (s SignInState) Valid() bool {
	return s == SignInStateAuthenticated || s == SignInStateChallengeRequired || s == SignInStateRejected
}

func canonicalASCII(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

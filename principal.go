// Package authentication defines framework-independent authentication contracts.
package authentication

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

const (
	// MaxClaims is the maximum number of entries in a principal claim map.
	MaxClaims = 128
	// MaxClaimDepth is the maximum nesting depth accepted in principal claims.
	MaxClaimDepth = 8
	// MaxClaimCollection is the maximum number of elements in a nested claim
	// map, slice, or array.
	MaxClaimCollection = 256
)

// ErrInvalidPrincipal identifies a principal that violates an identity
// invariant, exceeds its finite limits, or contains claims that cannot be
// copied safely. Errors never include supplied identity or claim values.
var ErrInvalidPrincipal = errors.New("authentication: invalid principal")

// PrincipalSpec contains the identity data used to construct a Principal.
// Callers may reuse or mutate its slices and maps after construction returns,
// but must not mutate them concurrently with construction. AuthenticatedAt and
// its time.Location are trusted clock/application metadata, retained unchanged.
type PrincipalSpec struct {
	Subject         string
	Method          string
	Issuer          string
	Audiences       []string
	TenantHints     []string
	Scopes          []string
	Claims          map[string]any
	AuthenticatedAt time.Time
}

// Principal is an immutable authenticated identity or the explicit anonymous
// identity. Its zero value is anonymous.
type Principal struct {
	subject         string
	method          string
	issuer          string
	audiences       []string
	tenantHints     []string
	scopes          []string
	claims          map[string]any
	authenticatedAt time.Time
}

// NewPrincipal validates and copies authenticated identity data using the
// default finite Principal limits. See NewPrincipalWithOptions to reduce them.
func NewPrincipal(spec PrincipalSpec) (Principal, error) {
	return NewPrincipalWithOptions(spec)
}

// NewPrincipalWithOptions admits authenticated identity data before copying it.
// Options may reduce, but not raise or disable, the default limits. Invalid
// options match both ErrInvalidPrincipal and ErrInvalidConfiguration; identity
// or claim admission failures match ErrInvalidPrincipal. Nil options are ignored.
//
// Each retained string is bounded, and its bytes count toward one aggregate
// budget, including repeated identity/list/claim-key/string-value occurrences.
// Each audience, tenant-hint and scope list has an independent count limit.
// Claims share one recursive value-count budget: scalars, nils and containers
// count once, interface wrappers and map keys do not. Repeated references count
// for each output occurrence. Existing claim count/depth/collection limits also
// apply. Retained strings have independent backing storage; defined scalar
// string types are preserved. AuthenticatedAt is retained unchanged.
func NewPrincipalWithOptions(spec PrincipalSpec, options ...PrincipalOption) (Principal, error) {
	configuration, err := newPrincipalConfig(options)
	if err != nil {
		return Principal{}, err
	}
	budget := principalBudget{
		configuration: configuration,
		stringBytes:   configuration.maxTotalStringBytes,
		claimNodes:    configuration.maxClaimNodes,
	}
	// Complete admission precedes all output allocation, string cloning and map
	// insertion. The caller owns synchronization of the borrowed input during
	// these validation and copy passes.
	if err := budget.admitString(spec.Subject); err != nil {
		return Principal{}, err
	}
	if err := budget.admitString(spec.Method); err != nil {
		return Principal{}, err
	}
	if err := budget.admitString(spec.Issuer); err != nil {
		return Principal{}, err
	}
	if spec.Subject == "" {
		return Principal{}, fmt.Errorf("%w: subject is required", ErrInvalidPrincipal)
	}
	if spec.Method == "" {
		return Principal{}, fmt.Errorf("%w: method is required", ErrInvalidPrincipal)
	}
	if err := budget.admitIdentityList("audience", spec.Audiences); err != nil {
		return Principal{}, err
	}
	if err := budget.admitIdentityList("tenant hint", spec.TenantHints); err != nil {
		return Principal{}, err
	}
	if err := budget.admitIdentityList("scope", spec.Scopes); err != nil {
		return Principal{}, err
	}
	if len(spec.Claims) > MaxClaims {
		return Principal{}, fmt.Errorf("%w: too many claims", ErrInvalidPrincipal)
	}

	if err := budget.admitClaimMap(spec.Claims); err != nil {
		return Principal{}, err
	}

	return Principal{
		subject:         strings.Clone(spec.Subject),
		method:          strings.Clone(spec.Method),
		issuer:          strings.Clone(spec.Issuer),
		audiences:       cloneStrings(spec.Audiences),
		tenantHints:     cloneStrings(spec.TenantHints),
		scopes:          cloneStrings(spec.Scopes),
		claims:          cloneAdmittedClaimMap(spec.Claims),
		authenticatedAt: spec.AuthenticatedAt,
	}, nil
}

// AnonymousPrincipal returns the explicit anonymous identity.
func AnonymousPrincipal() Principal { return Principal{} }

// IsAnonymous reports whether p represents absence of an authenticated identity.
func (p Principal) IsAnonymous() bool { return p.subject == "" }

// Subject returns the stable subject identifier.
func (p Principal) Subject() string { return p.subject }

// Method returns the authentication method that established the identity.
func (p Principal) Method() string { return p.method }

// Issuer returns the authority that asserted the identity, when applicable.
func (p Principal) Issuer() string { return p.issuer }

// Audiences returns a copy of the intended audiences.
func (p Principal) Audiences() []string { return cloneStrings(p.audiences) }

// TenantHints returns a copy of non-authoritative tenant hints.
func (p Principal) TenantHints() []string { return cloneStrings(p.tenantHints) }

// Scopes returns a copy of the scopes asserted by the credential. Scopes are
// authentication data and are not an authorization decision.
func (p Principal) Scopes() []string { return cloneStrings(p.scopes) }

// Claims returns a deep copy of the bounded claim set.
func (p Principal) Claims() map[string]any {
	// The private immutable set was already admitted. Copying it does not apply
	// a new policy that could reject or silently drop previously accepted claims.
	return cloneAdmittedClaimMap(p.claims)
}

// AuthenticatedAt returns the time at which the identity was authenticated,
// preserving the caller's trusted time.Location and timestamp representation.
func (p Principal) AuthenticatedAt() time.Time { return p.authenticatedAt }

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}

	cloned := append([]string(nil), values...)
	for i, value := range cloned {
		cloned[i] = strings.Clone(value)
	}
	return cloned
}

type principalBudget struct {
	configuration principalConfig
	stringBytes   int
	claimNodes    int
}

func (budget *principalBudget) admitString(value string) error {
	if len(value) > budget.configuration.maxStringBytes {
		return fmt.Errorf("%w: principal string size exceeded", ErrInvalidPrincipal)
	}
	if len(value) > budget.stringBytes {
		return fmt.Errorf("%w: principal total string size exceeded", ErrInvalidPrincipal)
	}
	// Subtracting only after the comparison avoids overflow in aggregate sums.
	budget.stringBytes -= len(value)
	return nil
}

func (budget *principalBudget) admitIdentityList(name string, values []string) error {
	if len(values) > budget.configuration.maxIdentityEntries {
		return fmt.Errorf("%w: principal identity list size exceeded", ErrInvalidPrincipal)
	}
	for _, value := range values {
		if err := budget.admitString(value); err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("%w: empty %s", ErrInvalidPrincipal, name)
		}
	}

	return nil
}

func (budget *principalBudget) admitClaimMap(claims map[string]any) error {
	if len(claims) > budget.claimNodes {
		return fmt.Errorf("%w: principal claim node count exceeded", ErrInvalidPrincipal)
	}
	for name, value := range claims {
		if err := budget.admitString(name); err != nil {
			return err
		}
		if name == "" {
			return fmt.Errorf("%w: empty claim name", ErrInvalidPrincipal)
		}
		if err := budget.admitClaimValue(reflect.ValueOf(value), 1); err != nil {
			return err
		}
	}
	return nil
}

func (budget *principalBudget) admitClaimValue(value reflect.Value, depth int) error {
	// Interfaces are representation wrappers, not additional retained values or
	// levels of claim nesting. Unwrap before charging the one output occurrence.
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			value = reflect.Value{}
			break
		}
		value = value.Elem()
	}
	if depth > MaxClaimDepth {
		return fmt.Errorf("%w: claim depth exceeded", ErrInvalidPrincipal)
	}
	if budget.claimNodes == 0 {
		return fmt.Errorf("%w: principal claim node count exceeded", ErrInvalidPrincipal)
	}
	budget.claimNodes--
	if !value.IsValid() {
		return nil
	}

	switch value.Kind() {
	case reflect.String:
		return budget.admitString(value.String())
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return nil
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String || value.Len() > MaxClaimCollection {
			return fmt.Errorf("%w: unsupported claim map", ErrInvalidPrincipal)
		}
		if value.Len() > budget.claimNodes {
			return fmt.Errorf("%w: principal claim node count exceeded", ErrInvalidPrincipal)
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if err := budget.admitString(iterator.Key().String()); err != nil {
				return err
			}
			if err := budget.admitClaimValue(iterator.Value(), depth+1); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		if value.Len() > MaxClaimCollection {
			return fmt.Errorf("%w: claim collection too large", ErrInvalidPrincipal)
		}
		if value.Len() > budget.claimNodes {
			return fmt.Errorf("%w: principal claim node count exceeded", ErrInvalidPrincipal)
		}
		for i := range value.Len() {
			if err := budget.admitClaimValue(value.Index(i), depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported claim value", ErrInvalidPrincipal)
	}
}

// These copy functions operate only after admission, or on private immutable
// data previously produced by them. No output is allocated during admission.
func cloneAdmittedClaimMap(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	cloned := make(map[string]any, len(claims))
	for name, value := range claims {
		cloned[strings.Clone(name)] = cloneAdmittedClaimValue(reflect.ValueOf(value))
	}
	return cloned
}

func cloneAdmittedClaimValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return cloneAdmittedClaimValue(value.Elem())
	case reflect.String:
		// Conversion keeps defined scalar-string types, notably json.Number.
		return reflect.ValueOf(strings.Clone(value.String())).Convert(value.Type()).Interface()
	case reflect.Map:
		cloned := make(map[string]any, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			cloned[strings.Clone(iterator.Key().String())] = cloneAdmittedClaimValue(iterator.Value())
		}
		return cloned
	case reflect.Slice, reflect.Array:
		cloned := make([]any, value.Len())
		for i := range value.Len() {
			cloned[i] = cloneAdmittedClaimValue(value.Index(i))
		}
		return cloned
	default:
		return value.Interface()
	}
}

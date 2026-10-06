package authentication

import "fmt"

const (
	// MaxPrincipalStringBytes is the default and ceiling for each retained string.
	MaxPrincipalStringBytes = 8 * 1024
	// MaxPrincipalIdentityEntries is the default and ceiling for each identity list.
	MaxPrincipalIdentityEntries = 256
	// MaxPrincipalTotalStringBytes is the default and ceiling for retained string bytes.
	MaxPrincipalTotalStringBytes = 64 * 1024
	// MaxPrincipalClaimNodes is the default and ceiling for recursive claim values.
	MaxPrincipalClaimNodes = 4096
)

type principalConfig struct {
	maxStringBytes      int
	maxIdentityEntries  int
	maxTotalStringBytes int
	maxClaimNodes       int
}

// PrincipalOption configures only Principal construction.
type PrincipalOption func(*principalConfig)

// WithMaxPrincipalStringBytes reduces the inclusive byte limit for each string.
func WithMaxPrincipalStringBytes(maximum int) PrincipalOption {
	return func(configuration *principalConfig) { configuration.maxStringBytes = maximum }
}

// WithMaxPrincipalIdentityEntries reduces the inclusive entry limit for each
// audience, tenant-hint, and scope list independently.
func WithMaxPrincipalIdentityEntries(maximum int) PrincipalOption {
	return func(configuration *principalConfig) { configuration.maxIdentityEntries = maximum }
}

// WithMaxPrincipalTotalStringBytes reduces the inclusive total retained string
// byte limit, counting every occurrence of identity data, claim keys and string values.
func WithMaxPrincipalTotalStringBytes(maximum int) PrincipalOption {
	return func(configuration *principalConfig) { configuration.maxTotalStringBytes = maximum }
}

// WithMaxPrincipalClaimNodes reduces the inclusive recursive claim-value limit.
// Containers, scalars and nil values each count once; interface wrappers do not.
func WithMaxPrincipalClaimNodes(maximum int) PrincipalOption {
	return func(configuration *principalConfig) { configuration.maxClaimNodes = maximum }
}

func newPrincipalConfig(options []PrincipalOption) (principalConfig, error) {
	configuration := principalConfig{
		maxStringBytes:      MaxPrincipalStringBytes,
		maxIdentityEntries:  MaxPrincipalIdentityEntries,
		maxTotalStringBytes: MaxPrincipalTotalStringBytes,
		maxClaimNodes:       MaxPrincipalClaimNodes,
	}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}
	if configuration.maxStringBytes <= 0 || configuration.maxStringBytes > MaxPrincipalStringBytes ||
		configuration.maxIdentityEntries <= 0 || configuration.maxIdentityEntries > MaxPrincipalIdentityEntries ||
		configuration.maxTotalStringBytes <= 0 || configuration.maxTotalStringBytes > MaxPrincipalTotalStringBytes ||
		configuration.maxClaimNodes <= 0 || configuration.maxClaimNodes > MaxPrincipalClaimNodes {
		return principalConfig{}, fmt.Errorf("%w: %w: principal limits", ErrInvalidPrincipal, ErrInvalidConfiguration)
	}
	return configuration, nil
}

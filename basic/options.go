package basic

import (
	"fmt"

	authentication "github.com/faustbrian/go-authentication/v2"
)

const (
	defaultMaxUsernameBytes = 8 * 1024
	defaultMaxPasswordBytes = 8 * 1024
)

type config struct {
	maxUsernameBytes int
	maxPasswordBytes int
}

// Option configures a static Basic authenticator.
type Option func(*config)

// WithMaxUsernameBytes sets an inclusive raw username-byte limit between one
// and 8 KiB. Without this option, the limit is 8 KiB.
func WithMaxUsernameBytes(maximum int) Option {
	return func(configuration *config) { configuration.maxUsernameBytes = maximum }
}

// WithMaxPasswordBytes sets an inclusive raw password-byte limit between one
// and 8 KiB. Without this option, the limit is 8 KiB.
func WithMaxPasswordBytes(maximum int) Option {
	return func(configuration *config) { configuration.maxPasswordBytes = maximum }
}

func staticConfiguration(options []Option) (config, error) {
	configuration := config{
		maxUsernameBytes: defaultMaxUsernameBytes,
		maxPasswordBytes: defaultMaxPasswordBytes,
	}
	for _, option := range options {
		if option != nil {
			option(&configuration)
		}
	}
	if configuration.maxUsernameBytes <= 0 || configuration.maxUsernameBytes > defaultMaxUsernameBytes ||
		configuration.maxPasswordBytes <= 0 || configuration.maxPasswordBytes > defaultMaxPasswordBytes {
		return config{}, fmt.Errorf("%w: Basic size bounds", authentication.ErrInvalidConfiguration)
	}
	return configuration, nil
}

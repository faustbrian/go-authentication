package basic

import (
	"errors"
	"fmt"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
)

func TestStaticConfigurationEnforcesPositiveByteLimits(t *testing.T) {
	for _, field := range []struct {
		name   string
		option func(int) Option
		limit  func(config) int
	}{
		{"username", WithMaxUsernameBytes, func(value config) int { return value.maxUsernameBytes }},
		{"password", WithMaxPasswordBytes, func(value config) int { return value.maxPasswordBytes }},
	} {
		for _, maximum := range []int{-1, 0, 1, 8192, 8193} {
			t.Run(fmt.Sprintf("%s/%d", field.name, maximum), func(t *testing.T) {
				configuration, err := staticConfiguration([]Option{field.option(maximum)})
				if maximum < 1 || maximum > 8192 {
					if !errors.Is(err, authentication.ErrInvalidConfiguration) {
						t.Fatalf("invalid byte limit %d returned error %v", maximum, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("valid byte limit %d was rejected: %v", maximum, err)
				}
				if field.limit(configuration) != maximum ||
					configuration.maxUsernameBytes < 1 || configuration.maxUsernameBytes > 8192 ||
					configuration.maxPasswordBytes < 1 || configuration.maxPasswordBytes > 8192 {
					t.Fatalf("successful configuration did not retain valid inclusive byte limits")
				}
			})
		}
	}
}

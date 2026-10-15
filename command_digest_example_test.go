package authentication_test

import (
	"fmt"

	auth "github.com/faustbrian/go-authentication/v2"
)

func ExampleOneTimeCode_CommandDigest() {
	code, err := auth.NewOneTimeCode("123456") // synthetic example only
	if err != nil {
		panic(err)
	}
	// Production composition supplies the coordinator's independently generated,
	// versioned fingerprint key and schema-owned canonical field path.
	_, err = code.CommandDigest([32]byte{1}, "otp.code")
	// Only the coordinator consumes the sensitive digest. Do not print it.
	fmt.Println(err == nil)
	// Output: true
}

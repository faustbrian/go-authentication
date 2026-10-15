package authentication_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestOpaqueCommandDigestMatchesCoordinatorProfile(t *testing.T) {
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	key := [32]byte{1}
	digest, err := code.CommandDigest(key, "otp.code")
	if err != nil {
		t.Fatal(err)
	}
	// Transaction contract: no NUL after domain, uint32 path bytes, uint64 secret bytes.
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte("identity-command-secret-v1\x00\x00\x00\x08otp.code\x00\x00\x00\x00\x00\x00\x00\x06123456"))
	if !hmac.Equal(digest[:], h.Sum(nil)) {
		t.Fatal("canonical transaction secret framing changed")
	}
}

func TestOpaqueCommandDigestBoundsAndDomainIsolation(t *testing.T) {
	code, _ := auth.NewOneTimeCode("123456")
	key := [32]byte{1}
	base, _ := code.CommandDigest(key, "otp.code")
	wrong, _ := auth.NewOneTimeCode("123457")
	for _, input := range []struct {
		code auth.OneTimeCode
		key  [32]byte
		path string
	}{
		{code, [32]byte{2}, "otp.code"}, {wrong, key, "otp.code"},
		{code, key, "otp.other"}, {code, key, "otp.code\x00"},
	} {
		other, err := input.code.CommandDigest(input.key, input.path)
		if err != nil || other == base {
			t.Fatal("changed secret/key/path collapsed")
		}
	}
	stored, _ := code.KeyedDigest(key, []byte("otp.code"))
	if base == stored {
		t.Fatal("command and challenge storage domains collapsed")
	}
	for _, path := range []string{"", strings.Repeat("x", 4097), "\xff"} {
		got, err := code.CommandDigest(key, path)
		if !errors.Is(err, auth.ErrInvalidProof) || got != ([32]byte{}) {
			t.Fatal("invalid path yielded digest")
		}
	}
	if got, err := code.CommandDigest([32]byte{}, "otp.code"); !errors.Is(err, auth.ErrInvalidProof) || got != ([32]byte{}) {
		t.Fatal("zero key yielded digest")
	}
	if got, err := (auth.OneTimeCode{}).CommandDigest(key, "otp.code"); !errors.Is(err, auth.ErrInvalidProof) || got != ([32]byte{}) {
		t.Fatal("zero code yielded digest")
	}
	for _, value := range []string{"1234", strings.Repeat("A", 128)} {
		bounded, err := auth.NewOneTimeCode(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"x", strings.Repeat("é", 2048), "otp.κωδικός"} {
			got, err := bounded.CommandDigest(key, path)
			if err != nil {
				t.Fatal(err)
			}
			// Independent lengths are byte lengths, never rune counts or normalized text.
			msg := []byte("identity-command-secret-v1")
			msg = binary.BigEndian.AppendUint32(msg, uint32(len(path)))
			msg = append(msg, path...)
			msg = binary.BigEndian.AppendUint64(msg, uint64(len(value)))
			msg = append(msg, value...)
			h := hmac.New(sha256.New, key[:])
			h.Write(msg)
			if !hmac.Equal(got[:], h.Sum(nil)) {
				t.Fatal("byte-bound command framing changed")
			}
		}
	}
	composed, _ := code.CommandDigest(key, "é")
	decomposed, _ := code.CommandDigest(key, "e\u0301")
	if composed == decomposed {
		t.Fatal("implicit Unicode normalization")
	}
}

func TestOpaqueCommandDigestDoesNotRetainCallerState(t *testing.T) {
	code, _ := auth.NewOneTimeCode("123456")
	key := [32]byte{1}
	path := "otp.code"
	want, _ := code.CommandDigest(key, path)
	key, path = [32]byte{2}, "other"
	if got, _ := code.CommandDigest([32]byte{1}, "otp.code"); got != want {
		t.Fatal("caller mutation retained")
	}
	if got, _ := code.CommandDigest(key, path); got == want {
		t.Fatal("different input collapsed")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if got, err := code.CommandDigest([32]byte{1}, "otp.code"); err != nil || got != want {
				t.Error("concurrent derivation changed")
			}
		})
	}
	wg.Wait()
}

func FuzzOpaqueCommandDigest(f *testing.F) {
	f.Add("123456", "otp.code")
	f.Add("1234", "é")
	f.Add("bad\x00", "\xff")
	f.Fuzz(func(t *testing.T, value, path string) {
		code, constructorErr := auth.NewOneTimeCode(value)
		got, err := code.CommandDigest([32]byte{1}, path)
		valid := constructorErr == nil && len(path) > 0 && len(path) <= 4096 && utf8.ValidString(path)
		if !valid {
			if !errors.Is(err, auth.ErrInvalidProof) || got != ([32]byte{}) {
				t.Fatal("invalid command digest admitted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("identity-command-secret-v1")
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(path)))
		msg = append(msg, path...)
		msg = binary.BigEndian.AppendUint64(msg, uint64(len(value)))
		msg = append(msg, value...)
		key := [32]byte{1}
		h := hmac.New(sha256.New, key[:])
		h.Write(msg)
		if !hmac.Equal(got[:], h.Sum(nil)) {
			t.Fatal("exact secret binding changed")
		}
	})
}

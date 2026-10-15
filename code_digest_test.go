package authentication_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
)

func TestOpaqueCodeKeyedDigestExactEncodingAndIsolation(t *testing.T) {
	const syntheticCode = "12345678"
	code, _ := auth.NewOneTimeCode(syntheticCode)
	recovery, _ := auth.NewRecoveryCode(syntheticCode)
	key := [32]byte{1}
	binding := []byte("scope")
	got, err := code.KeyedDigest(key, binding)
	if err != nil || got == ([32]byte{}) {
		t.Fatal("valid digest rejected")
	}
	// Independent literal framing: type domain, uint32 scope length, exact scope,
	// uint16 code length and exact constructor bytes. No production encoder used.
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte("authentication-one-time-code-digest-v1\x00\x00\x00\x00\x05scope\x00\x0812345678"))
	if !hmac.Equal(got[:], h.Sum(nil)) {
		t.Fatal("canonical digest encoding changed")
	}
	others := []struct {
		code  auth.OneTimeCode
		key   [32]byte
		scope []byte
	}{
		{code, [32]byte{2}, binding}, {code, key, []byte("other")},
		{code, key, []byte("scope\x00")},
	}
	different, _ := auth.NewOneTimeCode("12345679")
	others = append(others, struct {
		code  auth.OneTimeCode
		key   [32]byte
		scope []byte
	}{different, key, binding})
	for _, v := range others {
		other, e := v.code.KeyedDigest(v.key, v.scope)
		if e != nil || other == got {
			t.Fatal("digest binding collapsed")
		}
	}
	r, err := recovery.KeyedDigest(key, binding)
	if err != nil || r == got {
		t.Fatal("recovery and one-time domains collapsed")
	}
	h = hmac.New(sha256.New, key[:])
	h.Write([]byte("authentication-recovery-code-digest-v1\x00\x00\x00\x00\x05scope\x00\x0812345678"))
	if !hmac.Equal(r[:], h.Sum(nil)) {
		t.Fatal("recovery canonical digest changed")
	}
	// A returned digest must not alias key, scope or opaque storage.
	clear(binding)
	key = [32]byte{}
	repeat, e := code.KeyedDigest([32]byte{1}, []byte("scope"))
	if e != nil || repeat != got {
		t.Fatal("digest retained mutable inputs")
	}
	for _, v := range []any{code, recovery} {
		for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(format, v), syntheticCode) {
				t.Fatal("code formatting disclosed")
			}
		}
		b, e := json.Marshal(v)
		if e != nil || strings.Contains(string(b), syntheticCode) {
			t.Fatal("code JSON disclosed")
		}
	}
}

func TestOpaqueCodeDigestRejectsInvalidInputs(t *testing.T) {
	one, _ := auth.NewOneTimeCode("12345678")
	recovery, _ := auth.NewRecoveryCode("12345678")
	for _, derive := range []func([32]byte, []byte) ([32]byte, error){one.KeyedDigest, recovery.KeyedDigest} {
		for _, scope := range [][]byte{nil, {}, make([]byte, 4097)} {
			got, e := derive([32]byte{1}, scope)
			if !errors.Is(e, auth.ErrInvalidProof) || got != ([32]byte{}) {
				t.Fatal("invalid scope yielded digest")
			}
		}
		if got, e := derive([32]byte{}, []byte("scope")); !errors.Is(e, auth.ErrInvalidProof) || got != ([32]byte{}) {
			t.Fatal("zero key yielded digest")
		}
		for _, length := range []int{1, 4096} {
			if got, e := derive([32]byte{1}, make([]byte, length)); e != nil || got == ([32]byte{}) {
				t.Fatal("valid exact scope bounds rejected")
			}
		}
	}
	for _, derive := range []func([32]byte, []byte) ([32]byte, error){(auth.OneTimeCode{}).KeyedDigest, (auth.RecoveryCode{}).KeyedDigest} {
		if got, e := derive([32]byte{1}, []byte("scope")); !errors.Is(e, auth.ErrInvalidProof) || got != ([32]byte{}) {
			t.Fatal("zero code yielded digest")
		}
	}
}

func TestOpaqueDigestConcurrentDerivation(t *testing.T) {
	one, _ := auth.NewOneTimeCode("12345678")
	recovery, _ := auth.NewRecoveryCode("12345678")
	var wg sync.WaitGroup
	for _, derive := range []func([32]byte, []byte) ([32]byte, error){one.KeyedDigest, recovery.KeyedDigest} {
		want, _ := derive([32]byte{1}, []byte("scope"))
		for range 20 {
			wg.Go(func() {
				if got, e := derive([32]byte{1}, []byte("scope")); e != nil || got != want {
					t.Error("concurrent derivation changed")
				}
			})
		}
	}
	wg.Wait()
}

func FuzzOpaqueCodeKeyedDigest(f *testing.F) {
	f.Add("12345678", []byte("scope"))
	f.Add("1234", []byte{0})
	f.Add("123\x00", []byte("scope"))
	f.Fuzz(func(t *testing.T, value string, scope []byte) {
		one, oneErr := auth.NewOneTimeCode(value)
		recovery, recoveryErr := auth.NewRecoveryCode(value)
		for _, candidate := range []struct {
			valid  bool
			derive func([32]byte, []byte) ([32]byte, error)
		}{{oneErr == nil, one.KeyedDigest}, {recoveryErr == nil, recovery.KeyedDigest}} {
			digest, err := candidate.derive([32]byte{1}, scope)
			valid := candidate.valid && len(scope) > 0 && len(scope) <= 4096
			if valid {
				if err != nil || digest == ([32]byte{}) {
					t.Fatal("valid bounded digest rejected")
				}
				again, e := candidate.derive([32]byte{1}, scope)
				if e != nil || again != digest {
					t.Fatal("digest nondeterministic")
				}
			} else if !errors.Is(err, auth.ErrInvalidProof) || digest != ([32]byte{}) {
				t.Fatal("invalid digest input admitted")
			}
		}
	})
}

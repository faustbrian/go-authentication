package authentication

import (
	"strings"
	"testing"
)

func TestOpaqueStorageCopiesAndRetainsOnlyValidSecret(t *testing.T) {
	one, _ := NewOneTimeCode("1234")
	recovery, _ := NewRecoveryCode("12345678")
	if one.secret() != "1234" || recovery.secret() != "12345678" {
		t.Fatal("code storage changed")
	}
	if (OneTimeCode{}).secret != nil || (RecoveryCode{}).secret != nil {
		t.Fatal("zero code is initialized")
	}
	for _, value := range []string{"1234567\n", "1234567é", "1234567 "} {
		if _, err := NewRecoveryCode(value); err != ErrInvalidProof {
			t.Fatal("noncanonical recovery code accepted")
		}
	}
}

func TestClosedEnumBoundaries(t *testing.T) {
	for a := Assurance(0); a < Assurance(8); a++ {
		for required := Assurance(0); required < Assurance(8); required++ {
			want := a >= AssuranceSingleFactor && a <= AssurancePhishingResistant && required >= AssuranceSingleFactor && required <= AssurancePhishingResistant && a >= required
			if a.AtLeast(required) != want {
				t.Fatal("assurance ordering expanded")
			}
		}
	}
	for p := RecoveryPath(0); p < RecoveryPath(8); p++ {
		if p.Valid() != (p >= RecoveryPathEmail && p <= RecoveryPathAdministrator) {
			t.Fatal("recovery enum expanded")
		}
	}
	for s := SignInState(0); s < SignInState(8); s++ {
		if s.Valid() != (s >= SignInStateAuthenticated && s <= SignInStateRejected) {
			t.Fatal("sign-in enum expanded")
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 257), "invalid\xff", "invalid\n", "invalid\x7f"} {
		if identifier(value) {
			t.Fatal("invalid identifier accepted")
		}
	}
	if !identifier("valid-é") {
		t.Fatal("UTF-8 identifier rejected")
	}
}

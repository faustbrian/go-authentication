package authentication_test

import (
	auth "github.com/faustbrian/go-authentication/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzOpaqueCodeBoundaries(f *testing.F) {
	for _, value := range []string{"1234", "12345678", "", "\xff", "1234\n", strings.Repeat("a", 257)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1024 {
			return
		}
		ascii := true
		for i := range len(value) {
			if value[i] < 0x21 || value[i] > 0x7e {
				ascii = false
			}
		}
		_, oneErr := auth.NewOneTimeCode(value)
		_, recoveryErr := auth.NewRecoveryCode(value)
		_, purposeErr := auth.NewPurpose(value)
		if (oneErr == nil) != (ascii && len(value) >= 4 && len(value) <= 128) || (recoveryErr == nil) != (ascii && len(value) >= 8 && len(value) <= 256) || (purposeErr == nil) != (ascii && len(value) >= 1 && len(value) <= 128) {
			t.Fatal("constructor violated ASCII bounds")
		}
	})
}

func FuzzProofExactBinding(f *testing.F) {
	f.Add("tenant", "subject", "operation", "service")
	f.Add("", "\xff", "with space", "other")
	f.Add("tenant-\u0085", "subject-\u009f", "operation", "service-\u0080")
	f.Add("tenant-é", "subject-日本", "operation", "service-\u00a0")
	f.Fuzz(func(t *testing.T, tenant, subject, purpose, audience string) {
		if len(tenant)+len(subject)+len(purpose)+len(audience) > 4096 {
			return
		}
		for _, value := range []string{tenant, subject, audience} {
			valid := len(value) >= 1 && len(value) <= 256 && utf8.ValidString(value)
			for _, r := range value {
				if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
					valid = false
				}
			}
			spec := proofSpec()
			spec.Tenant, spec.Subject, spec.Method, spec.Audience = value, value, value, value
			if _, err := auth.NewProof(spec); (err == nil) != valid {
				t.Fatal("proof identity violated UTF-8 no-control bounds")
			}
		}
		proof, _ := auth.NewProof(proofSpec())
		use := proofUse()
		use.Tenant = tenant
		use.Subject = subject
		use.Purpose = auth.Purpose(purpose)
		use.Audience = audience
		if err := proof.Validate(use); err == nil && (tenant != proof.Tenant || subject != proof.Subject || use.Purpose != proof.Purpose || audience != proof.Audience) {
			t.Fatal("proof accepted different binding")
		}
	})
}

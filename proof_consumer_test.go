package authentication_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Go's actual external compiler, not source-text assertions, establishes that
// secret values cannot be made from literals, converted, or inspected.
func TestExternalConsumerCannotConstructOrDiscloseOpaqueCodes(t *testing.T) {
	for _, expression := range []string{
		`auth.OneTimeCode("1234")`,
		`auth.RecoveryCode("12345678")`,
		`auth.OneTimeCode{secret: func() string { return "1234" }}`,
		`auth.RecoveryCode{secret: func() string { return "12345678" }}`,
		`string(code)`,
		`code.secret()`,
		`auth.PermanentAccountProof{bindings: auth.PermanentAccountProofSpec{}}`,
		`auth.PermanentAccountProof{capability: nil}`,
	} {
		source := `package consumer
import auth "github.com/faustbrian/go-authentication/v2"
func use(){ code, _ := auth.NewOneTimeCode("1234"); _ = code; _ = ` + expression + ` }
`
		path := filepath.Join(t.TempDir(), "consumer.go")
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("go", "test", path)
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "[build failed]") {
			t.Fatalf("external access did not fail compilation: %v", err)
		}
		if !strings.Contains(string(output), "cannot") && !strings.Contains(string(output), "unexported") {
			t.Fatal("compiler failed for an unrelated reason")
		}
	}
}

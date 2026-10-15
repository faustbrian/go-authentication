package authentication

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func FuzzStrictAuthorityJSON(f *testing.F) {
	for _, value := range []string{`{"iss":"issuer"}`, `{"iss":"one","iss":"two"}`, `{"iss":"one","ISS":"two"}`, `{"ISS":"issuer"}`, `{"\u017Fub":"subject"}`, `{"owner":{"kind":"user","kind":"organization"}}`, `{"owner":{"kind":"user","KIND":"organization"}}`, `{"owner":{"unknown":1}}`, `{"parents":[{"ID":"parent"}]}`, `{"unknown":1}`, "\xff", strings.Repeat("[", 10) + strings.Repeat("]", 10)} {
		f.Add([]byte(value))
	}
	f.Add([]byte(`{"owner":{"id":"owner"},"actor":{"id":"actor"},"root_credential":{"id":"credential"},"root_grant":{"id":"grant"},"parents":[{"id":"parent"}]}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 20*1024 {
			return
		}
		var claims AccessTokenClaims
		if decodeClosedJSON(input, &claims) && (!json.Valid(input) || !authoritySchemaOracle(input, "claims")) {
			t.Fatal("noncanonical, unknown or duplicate authority JSON field accepted")
		}
	})
}

func TestAuthoritySchemaOracleRejectsAliasesUnknownsAndDuplicates(t *testing.T) {
	for _, value := range []string{`{"iss":"issuer"}`, `{"owner":{"id":"owner"},"actor":null,"root_credential":{"id":"credential"},"root_grant":{"id":"grant"},"parents":[{"id":"parent"}]}`} {
		if !authoritySchemaOracle([]byte(value), "claims") {
			t.Fatal("oracle rejected canonical field names")
		}
	}
	for _, value := range []string{`{"ISS":"issuer"}`, `{"iss":"one","iss":"two"}`, `{"unknown":1}`, `{"owner":{"ID":"owner"}}`, `{"actor":{"kind":"user","kind":"user"}}`, `{"root_credential":{"unknown":1}}`, `{"root_grant":{"VERSION":1}}`, `{"parents":[{"id":"parent","id":"parent"}]}`} {
		if authoritySchemaOracle([]byte(value), "claims") {
			t.Fatal("oracle accepted noncanonical field names or duplicates")
		}
	}
}

// This independent contract oracle uses exact wire-name sets, not Go's struct
// matching or the production scanner. Raw values preserve nested duplicates.
func authoritySchemaOracle(input []byte, schema string) bool {
	fields := "kind id version"
	switch schema {
	case "claims":
		fields = "iss aud sub client_id iat exp jti purpose environment method assurance owner actor tenant tenant_version client_version signing_version membership_id membership_version root_credential root_grant parents scopes"
	case "grant":
		fields = "id version expires_at"
	}
	allowed := make(map[string]bool)
	for _, name := range strings.Fields(fields) {
		allowed[name] = true
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	start, err := decoder.Token()
	if err != nil {
		return false
	}
	// Struct decoding admits null; semantic validation rejects absent identities.
	if start == nil {
		return true
	}
	if start != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return false
		}
		seen[name] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return false
		}
		if schema == "claims" {
			switch name {
			case "owner", "actor":
				if !authoritySchemaOracle(raw, "owner") {
					return false
				}
			case "root_credential", "root_grant":
				if !authoritySchemaOracle(raw, "grant") {
					return false
				}
			case "parents":
				var parents []json.RawMessage
				if json.Unmarshal(raw, &parents) != nil {
					return false
				}
				for _, parent := range parents {
					if !authoritySchemaOracle(parent, "grant") {
						return false
					}
				}
			}
		}
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func FuzzSignedValidityAgeBounds(f *testing.F) {
	f.Add(int64(0), int64(20*time.Second))
	f.Add(int64(0), int64(20*time.Second+1))
	f.Add(int64(0), int64(0))
	f.Fuzz(func(t *testing.T, startDelta, lifetime int64) {
		if startDelta < -int64(time.Hour) || startDelta > int64(time.Hour) {
			return
		}
		start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC).Add(time.Duration(startDelta))
		e := SignedValidityEvidence{Issuer: "issuer", Environment: "test", TokenID: "abcdefghijklmnopqrstuv", Tenant: "tenant", KeyID: "key", Dimensions: []DimensionValidity{{Dimension: ValidityDimension{Kind: ValidityOwner, ID: "subject", Version: 1}, Active: true, VerifiedAt: start, ValidUntil: start.Add(time.Duration(lifetime))}}}
		_, err := e.SigningBytes()
		if (err == nil) != (lifetime > 0 && lifetime <= int64(20*time.Second)) {
			t.Fatal("signed authority age bound changed")
		}
	})
}

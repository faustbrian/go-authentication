package authentication

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPolicyIdentifierAndASCIIInclusiveBoundaries(t *testing.T) {
	for _, value := range []string{"!", "~", "!~", strings.Repeat("a", 128)} {
		if !canonicalASCII(value, 1, 128) {
			t.Fatal("visible ASCII boundary rejected")
		}
	}
	for _, value := range []string{"", " ", "\x7f", "\x80", strings.Repeat("a", 129)} {
		if canonicalASCII(value, 1, 128) {
			t.Fatal("invalid ASCII accepted")
		}
	}
	for _, value := range []string{" ", "!", "~", "é", strings.Repeat("a", 256)} {
		if !identifier(value) {
			t.Fatal("valid identity boundary rejected")
		}
	}
	for _, value := range []string{"", "\x1f", "\x7f", "\xff", strings.Repeat("a", 257)} {
		if identifier(value) {
			t.Fatal("invalid identity accepted")
		}
	}
}

func TestAuthorityPolicyOwnerGrantAndScopePartitions(t *testing.T) {
	for _, kind := range []AuthorityOwnerKind{AuthorityOwnerUser, AuthorityOwnerOrganization, AuthorityOwnerWorkload} {
		if !validOwner(AuthorityOwner{Kind: kind, ID: "owner", Version: 1}) {
			t.Fatal("valid owner rejected")
		}
	}
	for _, owner := range []AuthorityOwner{{Kind: "unknown", ID: "owner", Version: 1}, {Kind: AuthorityOwnerUser, Version: 1}, {Kind: AuthorityOwnerUser, ID: "owner"}} {
		if validOwner(owner) {
			t.Fatal("invalid owner accepted")
		}
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, expiry := range []time.Time{{}, now, now.Add(time.Nanosecond)} {
		if !validGrant(AuthorityGrant{ID: "grant", Version: 1, ExpiresAt: expiry}, now) {
			t.Fatal("valid grant rejected")
		}
	}
	for _, grant := range []AuthorityGrant{{Version: 1}, {ID: "grant"}, {ID: "grant", Version: 1, ExpiresAt: now.Add(-time.Nanosecond)}} {
		if validGrant(grant, now) {
			t.Fatal("invalid grant accepted")
		}
	}
	scopes := make([]string, 128)
	for i := range scopes {
		scopes[i] = fmt.Sprintf("scope-%03d", i)
	}
	if !validScopes(nil) || !validScopes(scopes) {
		t.Fatal("bounded scopes rejected")
	}
	if validScopes(append(scopes, "extra")) || validScopes([]string{"same", "same"}) || validScopes([]string{""}) {
		t.Fatal("invalid scopes accepted")
	}
}

func TestAccessClaimsExactTimeAndDelegationLimits(t *testing.T) {
	now := time.Unix(1000, 0)
	a := &AuthorityAuthenticator{issuer: "issuer", environment: "test", audience: "resource", maximumDepth: 4}
	claims := AccessTokenClaims{Issuer: "issuer", Environment: "test", Audience: "resource", Subject: "owner", ClientID: "client", IssuedAt: 1000, ExpiresAt: 1300, TokenID: "abcdefghijklmnopqrstuv", Purpose: "access-token", Method: "password", Assurance: AssuranceSingleFactor, Owner: AuthorityOwner{Kind: AuthorityOwnerUser, ID: "owner", Version: 1}, Tenant: "tenant", TenantVersion: 1, ClientVersion: 1, SigningVersion: 1, RootCredential: AuthorityGrant{ID: "credential", Version: 1}, RootGrant: AuthorityGrant{ID: "root", Version: 1}}
	if !a.validClaims(claims, now) {
		t.Fatal("exact five-minute lifetime rejected")
	}
	for _, mutate := range []func(*AccessTokenClaims){
		func(c *AccessTokenClaims) { c.Issuer = "other" }, func(c *AccessTokenClaims) { c.Environment = "other" },
		func(c *AccessTokenClaims) { c.Audience = "other" }, func(c *AccessTokenClaims) { c.Purpose = "id-token" },
		func(c *AccessTokenClaims) { c.Subject = "" }, func(c *AccessTokenClaims) { c.ClientID = "" }, func(c *AccessTokenClaims) { c.Tenant = "" },
		func(c *AccessTokenClaims) { c.TokenID = "" }, func(c *AccessTokenClaims) { c.Method = "" }, func(c *AccessTokenClaims) { c.Assurance = AssuranceUnspecified },
		func(c *AccessTokenClaims) { c.TenantVersion = 0 }, func(c *AccessTokenClaims) { c.ClientVersion = 0 }, func(c *AccessTokenClaims) { c.SigningVersion = 0 },
		func(c *AccessTokenClaims) { c.Owner.ID = "other" }, func(c *AccessTokenClaims) { c.Owner.Kind = AuthorityOwnerWorkload },
		func(c *AccessTokenClaims) { c.MembershipVersion = 1 }, func(c *AccessTokenClaims) { c.MembershipID = "orphan" },
		func(c *AccessTokenClaims) { c.RootGrant.ID = c.TokenID }, func(c *AccessTokenClaims) { c.Scopes = []string{""} },
		func(c *AccessTokenClaims) { c.RootCredential.ID = "" }, func(c *AccessTokenClaims) { c.RootCredential.Version = 0 },
		func(c *AccessTokenClaims) { c.RootGrant.ID = "" }, func(c *AccessTokenClaims) { c.RootGrant.Version = 0 },
		func(c *AccessTokenClaims) { c.RootCredential.ExpiresAt = time.Unix(1299, 0) }, func(c *AccessTokenClaims) { c.RootGrant.ExpiresAt = time.Unix(1299, 0) },
	} {
		invalid := claims
		mutate(&invalid)
		if a.validClaims(invalid, now) {
			t.Fatal("invalid local authority claims accepted")
		}
	}
	actor := claims
	actor.Actor = &AuthorityOwner{Kind: AuthorityOwnerUser, ID: "actor", Version: 1}
	actor.MembershipID, actor.MembershipVersion = "membership", 1
	if !a.validClaims(actor, now) {
		t.Fatal("valid separate actor rejected")
	}
	for _, mutate := range []func(*AccessTokenClaims){
		func(c *AccessTokenClaims) { c.Actor.ID = "" }, func(c *AccessTokenClaims) { c.Actor.Kind = AuthorityOwnerOrganization },
		func(c *AccessTokenClaims) { c.MembershipID = "" }, func(c *AccessTokenClaims) { c.MembershipVersion = 0 },
	} {
		invalid := actor
		copy := *actor.Actor
		invalid.Actor = &copy
		mutate(&invalid)
		if a.validClaims(invalid, now) {
			t.Fatal("invalid actor or membership accepted")
		}
	}
	if a.validClaims(claims, time.Unix(1300, 0)) || a.validClaims(claims, time.Unix(999, 0)) {
		t.Fatal("exclusive time boundary accepted")
	}
	claims.ExpiresAt = 1301
	if a.validClaims(claims, now) {
		t.Fatal("overlong lifetime accepted")
	}
	claims.ExpiresAt = 1300
	delegated := claims
	delegated.RootGrant.ExpiresAt = time.Unix(1300, 0)
	delegated.Parents = []AuthorityGrant{{ID: "parent", Version: 1, ExpiresAt: time.Unix(1300, 0)}}
	if !a.validClaims(delegated, now) {
		t.Fatal("valid finite parent lineage rejected")
	}
	for _, mutate := range []func(*AccessTokenClaims){
		func(c *AccessTokenClaims) { c.Parents[0].ID = "" },
		func(c *AccessTokenClaims) { c.Parents[0].Version = 0 },
		func(c *AccessTokenClaims) { c.Parents[0].ExpiresAt = time.Unix(1299, 0) },
		func(c *AccessTokenClaims) { c.Parents[0].ExpiresAt = time.Time{} },
		func(c *AccessTokenClaims) { c.Parents[0].ID = c.RootGrant.ID },
		func(c *AccessTokenClaims) { c.Parents[0].ID = c.TokenID },
		func(c *AccessTokenClaims) { c.Parents[0].ExpiresAt = time.Unix(1301, 0) },
		func(c *AccessTokenClaims) { c.Parents = append(c.Parents, c.Parents[0]) },
		func(c *AccessTokenClaims) {
			c.Parents = append(c.Parents, AuthorityGrant{ID: "second", Version: 1, ExpiresAt: time.Unix(1301, 0)})
		},
	} {
		invalid := delegated
		invalid.Parents = append([]AuthorityGrant(nil), delegated.Parents...)
		mutate(&invalid)
		if a.validClaims(invalid, now) {
			t.Fatal("invalid local parent lineage accepted")
		}
	}
	for i := 0; i < 4; i++ {
		claims.Parents = append(claims.Parents, AuthorityGrant{ID: fmt.Sprintf("parent-%d", i), Version: 1, ExpiresAt: time.Unix(1300, 0)})
	}
	if !a.validClaims(claims, now) {
		t.Fatal("exact configured delegation depth rejected")
	}
	claims.Parents = append(claims.Parents, AuthorityGrant{ID: "extra", Version: 1, ExpiresAt: time.Unix(1300, 0)})
	if a.validClaims(claims, now) {
		t.Fatal("excessive delegation depth accepted")
	}
	claims.Parents = nil
	claims.IssuedAt, claims.ExpiresAt = 0, 60
	if a.validClaims(claims, time.Unix(0, 0)) {
		t.Fatal("nonpositive issued time accepted")
	}
}

func scanPolicyJSON(value string) bool {
	return scanJSONValue(json.NewDecoder(strings.NewReader(value)), 0)
}

func TestAuthorityParserExactDepthKeyAndCollectionLimits(t *testing.T) {
	for _, count := range []int{8, 9} {
		value := strings.Repeat("[", count) + "0" + strings.Repeat("]", count)
		if scanPolicyJSON(value) != (count == 8) {
			t.Fatal("JSON depth boundary changed")
		}
		object := strings.Repeat(`{"value":`, count) + "0" + strings.Repeat("}", count)
		if scanPolicyJSON(object) != (count == 8) {
			t.Fatal("JSON object depth boundary changed")
		}
	}
	for _, count := range []int{128, 129} {
		entries := make([]string, count)
		for i := range entries {
			entries[i] = fmt.Sprintf("\"key-%03d\":0", i)
		}
		if scanPolicyJSON("{"+strings.Join(entries, ",")+"}") != (count == 128) {
			t.Fatal("JSON key count boundary changed")
		}
	}
	for _, size := range []int{256, 257} {
		if scanPolicyJSON("{\""+strings.Repeat("a", size)+"\":0}") != (size == 256) {
			t.Fatal("JSON key size boundary changed")
		}
		if scanPolicyJSON("["+strings.Repeat("0,", size-1)+"0]") != (size == 256) {
			t.Fatal("JSON array size boundary changed")
		}
	}
	for _, value := range []string{"{\"a\":0,\"a\":1}", "[0,", "{1:0}"} {
		if scanPolicyJSON(value) {
			t.Fatal("malformed or duplicate JSON accepted")
		}
	}
	for _, size := range []int{16384, 16385} {
		var projection struct{}
		if decodeClosedJSON([]byte("{}"+strings.Repeat(" ", size-2)), &projection) != (size == 16384) {
			t.Fatal("JSON byte size boundary changed")
		}
	}
	var projection struct {
		Value string `json:"value"`
	}
	if decodeClosedJSON([]byte("{\"value\":\"\xff\"}"), &projection) {
		t.Fatal("invalid UTF-8 accepted")
	}
}

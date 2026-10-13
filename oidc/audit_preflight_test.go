package oidc

import "testing"

func TestJSONObjectRequiresTrueEndOfInput(t *testing.T) {
	for _, valid := range []string{`{}`, "{} \t\r\n"} {
		if err := inspectJSONObject([]byte(valid), 64, 4); err != nil {
			t.Errorf("valid JSON boundary rejected: %v", err)
		}
	}
	for _, suffix := range []string{"#", "{", "true", " null"} {
		if err := inspectJSONObject([]byte(`{}`+suffix), 64, 4); err == nil {
			t.Error("non-EOF trailing JSON admitted")
		}
	}
}

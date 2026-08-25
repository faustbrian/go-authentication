.PHONY: conformance interoperability

conformance:
	GOWORK=off go test ./... -count=1

interoperability:
	../.golib/scripts/test-oidc-keycloak-interoperability.sh

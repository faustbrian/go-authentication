.PHONY: api conformance interoperability

api:
	./scripts/check-api.sh

conformance:
	./scripts/check-conformance.sh

interoperability: conformance

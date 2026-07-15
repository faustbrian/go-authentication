#!/bin/sh
set -eu

if [ "$(go list -m all | wc -l | tr -d ' ')" -ne 1 ]; then
	printf '%s\n' 'root module must remain dependency-free' >&2
	exit 1
fi

dependencies=$(cd authotel && go list -deps .)
for forbidden in go.opentelemetry.io/otel/sdk github.com/faustbrian/go-telemetry; do
	if printf '%s\n' "$dependencies" | grep -Eq "^${forbidden}(/|$)"; then
		printf 'authotel has forbidden production dependency: %s\n' "$forbidden" >&2
		exit 1
	fi
done

for module in . jwt oidc authotel; do
	dependencies=$(cd "$module" && go list -deps ./...)
	for forbidden in \
		github.com/faustbrian/go-service \
		github.com/faustbrian/go-http-client \
		github.com/faustbrian/go-authorization
	do
		if printf '%s\n' "$dependencies" | grep -Eq "^${forbidden}(/|$)"; then
			printf '%s has forbidden production dependency: %s\n' \
				"$module" "$forbidden" >&2
			exit 1
		fi
	done
done

#!/bin/sh
set -eu

root=$(pwd)
apidiff_version=v0.0.0-20250218142911-aa4b98e5adaa

check() {
	directory=$1
	module=$2
	baseline=$3
	current=$(mktemp "${TMPDIR:-/tmp}/go-auth-api.XXXXXX")
	report=$(mktemp "${TMPDIR:-/tmp}/go-auth-api-report.XXXXXX")
	trap 'rm -f "$current" "$report"' EXIT HUP INT TERM
	if [ ! -f "$root/$baseline" ]; then
		printf 'missing API baseline: %s\n' "$baseline" >&2
		exit 1
	fi
	(
		cd "$directory"
		go run "golang.org/x/exp/cmd/apidiff@${apidiff_version}" -m -w "$current" "$module"
		go run "golang.org/x/exp/cmd/apidiff@${apidiff_version}" \
			-m -incompatible "$root/$baseline" "$current" >"$report"
	)
	if [ -s "$report" ]; then
		printf 'incompatible exported API changes in %s:\n' "$module" >&2
		cat "$report" >&2
		exit 1
	fi
	rm -f "$current" "$report"
	trap - EXIT HUP INT TERM
}

check . github.com/faustbrian/go-authentication api/root.txt
check jwt github.com/faustbrian/go-authentication/jwt api/jwt.txt
check oidc github.com/faustbrian/go-authentication/oidc api/oidc.txt
check authotel github.com/faustbrian/go-authentication/authotel api/authotel.txt

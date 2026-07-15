module github.com/faustbrian/go-authentication/oidc

go 1.26.5

require (
	github.com/coreos/go-oidc/v3 v3.20.0
	github.com/faustbrian/go-authentication v1.0.0
	github.com/go-jose/go-jose/v4 v4.1.4
)

require golang.org/x/oauth2 v0.36.0 // indirect

replace github.com/faustbrian/go-authentication => ..

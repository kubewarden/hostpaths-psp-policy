module github.com/kubewarden/go-policy-template

go 1.22

toolchain go1.24.0

require (
	github.com/francoispqt/onelog v0.0.0-20190306043706-8c2bb31b10a4
	github.com/kubewarden/gjson v1.7.2
	github.com/kubewarden/policy-sdk-go v0.11.0
	github.com/wapc/wapc-guest-tinygo v0.3.3
)

require (
	github.com/francoispqt/gojay v0.0.0-20181220093123-f2cc13a668ca // indirect
	github.com/go-openapi/strfmt v0.21.3 // indirect
	github.com/kubewarden/k8s-objects v1.29.0-kw1 // indirect
	github.com/tidwall/match v1.0.3 // indirect
	github.com/tidwall/pretty v1.0.2 // indirect
)

replace github.com/go-openapi/strfmt => github.com/kubewarden/strfmt v0.1.3

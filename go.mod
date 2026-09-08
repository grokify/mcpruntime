module github.com/plexusone/omniskill

go 1.26.0

require (
	github.com/grokify/mogo v0.74.8
	github.com/modelcontextprotocol/go-sdk v1.7.0
	golang.ngrok.com/ngrok v1.13.0
	golang.org/x/mod v0.41.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/inconshreveable/log15 v3.0.0-testing.5+incompatible // indirect
	github.com/inconshreveable/log15/v3 v3.1.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.ngrok.com/muxado/v2 v2.0.1 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

// Force log15/v3 to version compatible with ngrok v1.12.0 (has ext.RandId)
replace github.com/inconshreveable/log15/v3 => github.com/inconshreveable/log15/v3 v3.0.0-testing.5

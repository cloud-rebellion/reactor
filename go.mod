module github.com/bright-interaction/reactor

go 1.25.10

// Pinned to the toolchain the container image already builds with. Without this,
// go.mod permits an older Go and govulncheck reports the standard-library
// vulnerabilities fixed in 1.26.6 (net/http ReadHeaderTimeout on the unencrypted
// HTTP/2 check, encoding/xml and encoding/asn1 decode recursion, x/net/idna
// Punycode label rejection) as reachable. The pin makes the
// version that keeps this safe a guarantee rather than a property of the base image.
toolchain go1.26.6

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc
	github.com/getsentry/sentry-go v0.47.0
	github.com/go-chi/chi/v5 v5.3.0
	github.com/go-webauthn/webauthn v0.17.4
	github.com/jackc/pgx/v5 v5.9.2
	github.com/pquerna/otp v1.5.0
	github.com/pressly/goose/v3 v3.27.1
	github.com/robfig/cron/v3 v3.0.1
	github.com/yuin/goldmark v1.7.17
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	modernc.org/sqlite v1.50.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	modernc.org/libc v1.72.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

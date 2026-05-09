# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `cmd/go-socks5` and `cmd/hashpass` binary layout under `cmd/`.
- `internal/config` package with TOML + environment-variable overrides and
  full validation.
- `internal/proxy` package: context-aware accept loop with `MaxConns`
  semaphore, configurable handshake / dial / idle / shutdown timeouts,
  graceful shutdown via `signal.NotifyContext`.
- `internal/metrics` Prometheus collectors:
  `socks5_active_connections`, `socks5_connections_total`,
  `socks5_auth_failures_total`, `socks5_dial_errors_total`,
  `socks5_handshake_errors_total`, `socks5_bytes_proxied_total{direction}`,
  `socks5_build_info{version,goversion,os,arch}`.
- Optional `metrics_addr` (Prometheus `/metrics`) and `pprof_addr`
  (`net/http/pprof`) sidecars, off by default.
- `argon2id` password hashing in PHC string format with `crypto/subtle`
  constant-time comparison and dummy-hash timing-oracle defence; configurable
  parameter caps (memory ≤ 4 GiB, time ≤ 100, parallelism ≤ 64).
- `cmd/hashpass` CLI for generating PHC strings (stdin only).
- Multi-stage Dockerfile producing a `gcr.io/distroless/static-debian12:nonroot` image.
- GitHub Actions: `ci.yml` (vet + race tests + coverage + lint + govulncheck),
  `release.yml` (GoReleaser, GHCR), `fuzz.yml` (nightly).
- `.golangci.yml` v2 configuration enabling `errcheck`, `errorlint`,
  `gosec`, `revive`, `gofumpt`, `prealloc`, `bodyclose`, `noctx` etc.
- Fuzz tests for the SOCKS5 request parser.
- Integration tests using `net/http`'s built-in SOCKS5 client.
- `SECURITY.md`, `CHANGELOG.md`.

### Changed
- **Breaking** — module path is now `github.com/gumeniukcom/go-socks5`.
- **Breaking** — credential storage replaces `base64(SHA1(password))` with
  `argon2id` PHC strings. Operators must re-issue credentials with `hashpass`.
- Logging migrated from `github.com/rs/zerolog` to stdlib `log/slog`.
- Default config gains explicit `max_conns`, `*_timeout`, `log_format`, `log_level`.

### Removed
- Legacy `vendor/` directory (replaced by Go modules with `go.sum`).
- `.travis.yml`, `.gometalinter.json`, `BENCHMARKS.md`.
- Top-level `proxy/` and `main.go` (moved into the `cmd/` + `internal/` tree).

### Security
- Fixed pre-existing **auth bypass**: auth failure used to fall through to a
  success write; failed credentials now correctly close the session.
- Fixed pre-existing **auth bypass via `sync.Pool` reuse**: the previous
  pool returned `Connection` values with a nil `Authorizer`.
- Fixed pre-existing **`hash.Hash` data race** in the SHA1 pool (`Put`
  before `Reset`); the entire SHA1 path is gone.
- Fixed pre-existing **goroutine leak** in the accept loop on shutdown.
- Added per-connection deadlines and dial timeouts; idle clients can no
  longer hold connections forever.
- Removed `unsafe.Pointer` byte-to-string aliasing in the auth path.

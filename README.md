# go-socks5

[![CI](https://github.com/gumeniukcom/go-socks5/actions/workflows/ci.yml/badge.svg)](https://github.com/gumeniukcom/go-socks5/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gumeniukcom/go-socks5.svg)](https://pkg.go.dev/github.com/gumeniukcom/go-socks5)

Minimal SOCKS5 proxy server in Go. Implements `CONNECT` per [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928) and optional username/password auth per [RFC 1929](https://datatracker.ietf.org/doc/html/rfc1929) using argon2id for credential storage.

## Limitations

- `CONNECT` only. `BIND` and `UDP ASSOCIATE` are intentionally not implemented and respond with reply code `0x07` (command not supported).
- IPv4, IPv6, and domain address types are supported.

## Quick start (Docker)

```bash
docker run --rm -p 1080:8008 ghcr.io/gumeniukcom/go-socks5:latest
```

The default image listens on `0.0.0.0:8008` with auth disabled. Mount your own config to enable auth:

```bash
docker run --rm -p 1080:8008 \
    -v $PWD/config.toml:/etc/go-socks5/config.toml:ro \
    ghcr.io/gumeniukcom/go-socks5:latest
```

## Build from source

```bash
make build
./bin/go-socks5 -c config.toml
```

Requires Go 1.24 or newer.

## Configuration

`config.toml` (full reference):

```toml
listen           = "0.0.0.0:8008"
auth             = true
max_conns        = 1024
handshake_timeout = "30s"
dial_timeout     = "10s"
idle_timeout     = "5m"
shutdown_timeout = "30s"

# Optional sidecars (the metrics endpoint also serves /healthz when enabled).
metrics_addr = "0.0.0.0:9090"   # Prometheus /metrics + /healthz
pprof_addr   = "127.0.0.1:6060" # net/http/pprof

log_format = "json"   # json | text
log_level  = "info"   # debug | info | warn | error

[[users]]
    login = "alice"
    pass  = "$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>"
```

Every setting may be overridden via environment variables:

| Env                 | Maps to        |
| ------------------- | -------------- |
| `SOCKS5_LISTEN`     | `listen`       |
| `SOCKS5_AUTH`       | `auth`         |
| `SOCKS5_MAX_CONNS`  | `max_conns`    |
| `SOCKS5_METRICS_ADDR` | `metrics_addr` |
| `SOCKS5_PPROF_ADDR` | `pprof_addr`   |
| `SOCKS5_LOG_FORMAT` | `log_format`   |
| `SOCKS5_LOG_LEVEL`  | `log_level`    |

## Auth setup

Generate a password hash:

```bash
echo -n "hunter2" | ./bin/hashpass
# $argon2id$v=19$m=65536,t=3,p=4$ZGV0ZXJtaW5pc3RpY3NhbHQ$...
```

Paste the output into the `pass` field of a `[[users]]` block. Hashes are bound to fixed argon2id parameters (`m=64MiB, t=3, p=4`); raise them via the on-disk hash format if you re-issue credentials in the future.

> **Migration note:** earlier releases stored passwords as `base64(SHA1(password))` (htpasswd `-nbs` format). That scheme is cryptographically broken and is no longer accepted. All credentials must be re-issued with `hashpass`.

## Observability

When `metrics_addr` is set, the following Prometheus metrics are exported on `/metrics`:

- `socks5_active_connections` (gauge)
- `socks5_connections_total` (counter)
- `socks5_auth_failures_total` (counter)
- `socks5_dial_errors_total` (counter)
- `socks5_handshake_errors_total` (counter)
- `socks5_bytes_proxied_total{direction}` (counter; `direction = client_to_target | target_to_client`)
- `socks5_build_info{version, goversion, os, arch}` (gauge, value `1`)

The same listener also serves `/healthz` (returns `200 ok`) for liveness/readiness probes.

Logs are emitted on stderr in JSON or text via `log/slog`.

## Development

```bash
make test     # go test -race
make lint     # golangci-lint run
make vuln     # govulncheck
make cover    # coverage report -> cover.html
make fuzz     # 30s of fuzzing for protocol parsers
```

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT — see [LICENSE](LICENSE).

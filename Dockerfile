# syntax=docker/dockerfile:1.7
FROM golang:1.24-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/go-socks5 ./cmd/go-socks5

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/gumeniukcom/go-socks5"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.description="Minimal SOCKS5 proxy server in Go"
COPY --from=builder /out/go-socks5 /usr/local/bin/go-socks5
COPY config.toml /etc/go-socks5/config.toml
EXPOSE 8008
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/go-socks5", "-c", "/etc/go-socks5/config.toml"]

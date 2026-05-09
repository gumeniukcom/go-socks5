# Security Policy

## Supported Versions

Only the latest minor release receives security fixes.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately via email to **i@gumeniuk.com**. Include:

1. A description of the issue and its impact.
2. Steps to reproduce, ideally with a minimal proof of concept.
3. The affected version (`go-socks5 -version`).

You should receive an acknowledgement within **72 hours**. If you do not, please follow up on the same thread.

Public GitHub issues are not the right venue for vulnerability reports — please use email so we can coordinate a fix and disclosure timeline.

## Hardening Notes for Operators

- Run the proxy in a container or with a dedicated unprivileged user; never as root.
- Always enable authentication (`auth = true`) when exposing the proxy to networks you do not control.
- Use a frontend that enforces TLS termination and per-source rate limiting; this proxy does not implement either.
- Keep the binary up to date — `govulncheck` runs in CI for every build.

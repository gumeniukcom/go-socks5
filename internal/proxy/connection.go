package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gumeniukcom/go-socks5/internal/metrics"
)

// connection serves one client TCP connection: handshake → request → command.
type connection struct {
	conn             net.Conn
	auth             Authorizer
	logger           *slog.Logger
	metrics          *metrics.Metrics
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	idleTimeout      time.Duration
}

// serve runs the full per-connection state machine. The connection is closed
// exactly once via a sync.Once shared between the cancel-watcher goroutine
// (which fires on ctx cancellation) and the deferred shutdown sequence.
func (c *connection) serve(ctx context.Context) {
	connCtx, cancel := context.WithCancel(ctx)

	var closeOnce sync.Once
	closeConn := func() {
		closeOnce.Do(func() { _ = c.conn.Close() })
	}

	// Register the deferred shutdown BEFORE starting the watcher goroutine
	// so any panic between here and the goroutine launch still drains it.
	watcherDone := make(chan struct{})
	defer func() {
		cancel()
		<-watcherDone
	}()
	go func() {
		defer close(watcherDone)
		<-connCtx.Done()
		closeConn()
	}()

	// Handshake deadline applies until we either reject or transition to data.
	if err := c.conn.SetDeadline(time.Now().Add(c.handshakeTimeout)); err != nil {
		c.logger.Debug("set handshake deadline", "err", err)
	}

	if err := c.handshake(connCtx); err != nil {
		c.metrics.HandshakeErrors.Inc()
		c.logger.Debug("handshake failed", "remote", c.conn.RemoteAddr(), "err", err)
		return
	}

	// Read request (still under handshake deadline).
	req, err := readRequest(c.conn)
	if err != nil {
		c.metrics.HandshakeErrors.Inc()
		c.logger.Debug("read request failed", "err", err)
		// Best-effort: tell client about parse failures we can map.
		c.writeRequestFailure(err)
		return
	}

	// Clear deadline before entering data-transfer phase; per-IO idle
	// timeout (set in copyWithIdle) takes over.
	if err := c.conn.SetDeadline(time.Time{}); err != nil {
		c.logger.Debug("clear deadline", "err", err)
	}

	cmd := &command{
		req:         req,
		clientConn:  c.conn,
		logger:      c.logger,
		metrics:     c.metrics,
		dialTimeout: c.dialTimeout,
		idleTimeout: c.idleTimeout,
	}
	reply, ferr := cmd.fire(connCtx)
	if reply != repSuccess {
		// Command refused before any data was sent; reply now.
		_, _ = c.conn.Write(errorResponseForRequest(req, reply))
	}
	if ferr != nil {
		c.logger.Debug("command finished with error", "command", req.command, "err", ferr)
	}
}

// handshake performs SOCKS5 method negotiation per RFC 1928 §3 and, when the
// client selects username/password, the sub-negotiation in RFC 1929.
func (c *connection) handshake(ctx context.Context) error {
	var version byte
	if err := binary.Read(c.conn, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if version != socks5Version {
		// Best-effort reply; the client may not understand but we shouldn't
		// silently hang the connection on the unsupported-version branch.
		_, _ = c.conn.Write([]byte{socks5Version, authMethodNoneAcceptable})
		return fmt.Errorf("unsupported SOCKS version 0x%02x", version)
	}

	var methodCount byte
	if err := binary.Read(c.conn, binary.BigEndian, &methodCount); err != nil {
		return fmt.Errorf("read method count: %w", err)
	}
	if methodCount == 0 {
		_, _ = c.conn.Write([]byte{socks5Version, authMethodNoneAcceptable})
		return errors.New("client offered zero auth methods")
	}
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(c.conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	wantAuth := c.auth != nil && c.auth.ShouldAuth()

	switch {
	case !wantAuth && bytes.IndexByte(methods, authMethodNoAuth) != -1:
		_, err := c.conn.Write([]byte{socks5Version, authMethodNoAuth})
		return err
	case wantAuth && bytes.IndexByte(methods, authMethodUserPassword) != -1:
		return c.authenticate(ctx)
	default:
		_, _ = c.conn.Write([]byte{socks5Version, authMethodNoneAcceptable})
		return errors.New("no acceptable authentication method")
	}
}

// authenticate runs the RFC 1929 username/password sub-negotiation.
func (c *connection) authenticate(ctx context.Context) error {
	if _, err := c.conn.Write([]byte{socks5Version, authMethodUserPassword}); err != nil {
		return fmt.Errorf("write method selection: %w", err)
	}

	var subVersion byte
	if err := binary.Read(c.conn, binary.BigEndian, &subVersion); err != nil {
		return fmt.Errorf("read subneg version: %w", err)
	}
	if subVersion != authSubVersion {
		_, _ = c.conn.Write([]byte{authSubVersion, authStatusFailure})
		return fmt.Errorf("unsupported subneg version 0x%02x", subVersion)
	}

	username, err := readLengthPrefixed(c.conn)
	if err != nil {
		_, _ = c.conn.Write([]byte{authSubVersion, authStatusFailure})
		return fmt.Errorf("read username: %w", err)
	}
	password, err := readLengthPrefixed(c.conn)
	if err != nil {
		_, _ = c.conn.Write([]byte{authSubVersion, authStatusFailure})
		return fmt.Errorf("read password: %w", err)
	}

	if !c.auth.AuthLoginPassword(ctx, string(username), password) {
		c.metrics.AuthFailures.Inc()
		_, _ = c.conn.Write([]byte{authSubVersion, authStatusFailure})
		return errors.New("invalid credentials")
	}

	if _, err := c.conn.Write([]byte{authSubVersion, authStatusSuccess}); err != nil {
		return fmt.Errorf("write auth success: %w", err)
	}
	return nil
}

// readLengthPrefixed reads a one-byte length followed by that many bytes.
func readLengthPrefixed(r io.Reader) ([]byte, error) {
	var n byte
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("zero-length field")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// errorResponseForRequest synthesizes a reply for a failed command. It uses
// the request's address type if known; otherwise falls back to a 0.0.0.0:0
// IPv4 reply (RFC 1928 says BND.ADDR/BND.PORT may be zeros on failure).
func errorResponseForRequest(req *request, code byte) []byte {
	if req == nil {
		return errorResponse(code)
	}
	r := response{reply: code, addrType: req.addrType, addr: req.addr, port: 0}
	switch req.addrType {
	case addrTypeIPv4, addrTypeIPv6, addrTypeDomain:
		// keep as-is
	default:
		return errorResponse(code)
	}
	buf, err := r.marshal()
	if err != nil {
		return errorResponse(code)
	}
	return buf
}

// writeRequestFailure attempts to map common request-parse errors to a SOCKS5
// reply byte and writes a minimal response.
func (c *connection) writeRequestFailure(err error) {
	code := repServerFailure
	switch {
	case errors.Is(err, errAddrTypeNotSupp):
		code = repAddrTypeNotSupported
	case errors.Is(err, errBadVersion), errors.Is(err, errBadReserved):
		code = repServerFailure
	}
	_, _ = c.conn.Write(errorResponse(code))
}

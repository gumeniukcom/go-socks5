package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gumeniukcom/go-socks5/internal/metrics"
)

// command executes a single SOCKS5 request after the handshake.
type command struct {
	req         *request
	clientConn  net.Conn
	logger      *slog.Logger
	metrics     *metrics.Metrics
	dialTimeout time.Duration
	idleTimeout time.Duration
}

// fire dispatches the parsed command to its handler. The returned reply byte
// is what the caller should write to the client; only repSuccess means data
// has already been transferred and no follow-up reply is needed.
func (c *command) fire(ctx context.Context) (byte, error) {
	switch c.req.command {
	case cmdConnect:
		return c.connect(ctx)
	case cmdBind, cmdUDPAssociate:
		return repCommandNotSupported, nil
	default:
		return repCommandNotSupported, nil
	}
}

// connect handles the CONNECT command per RFC 1928 §6: dial the requested
// target, write a success reply with the bound address, and pipe data
// bidirectionally until either side closes or context is cancelled.
func (c *command) connect(ctx context.Context) (byte, error) {
	target := c.req.fqdn()

	// Single source of truth for dial deadlines: the context. Setting both
	// Dialer.Timeout and a context deadline produces inconsistent error
	// types depending on which fires first.
	dialCtx, cancelDial := context.WithTimeout(ctx, c.dialTimeout)
	defer cancelDial()

	var dialer net.Dialer
	upstream, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		c.metrics.DialErrors.Inc()
		c.logger.Warn("upstream dial failed", "target", target, "err", err)
		return mapDialError(err), err
	}
	defer func() { _ = upstream.Close() }()

	// Build success reply describing the local end of the upstream connection.
	resp := &response{reply: repSuccess}
	if err := resp.fillFromLocalAddr(upstream.LocalAddr().String()); err != nil {
		return repServerFailure, err
	}
	buf, err := resp.marshal()
	if err != nil {
		return repServerFailure, err
	}
	if _, err := c.clientConn.Write(buf); err != nil {
		return repServerFailure, err
	}

	c.pipe(ctx, upstream)
	return repSuccess, nil
}

// pipe copies bytes in both directions and returns when the slowest side
// finishes. ctx cancellation closes both connections so the io.Copy loops
// unblock immediately.
func (c *command) pipe(ctx context.Context, upstream net.Conn) {
	pipeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	closeOnce := sync.Once{}
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = c.clientConn.Close()
			_ = upstream.Close()
		})
	}

	// Cancel-on-context closes both sides so io.Copy unblocks.
	doneCancelWatch := make(chan struct{})
	go func() {
		defer close(doneCancelWatch)
		<-pipeCtx.Done()
		closeBoth()
	}()

	idle := c.idleTimeout
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer cancel()
		n, _ := copyWithIdle(upstream, c.clientConn, idle)
		c.metrics.BytesProxied.WithLabelValues("client_to_target").Add(float64(n))
	}()

	go func() {
		defer wg.Done()
		defer cancel()
		n, _ := copyWithIdle(c.clientConn, upstream, idle)
		c.metrics.BytesProxied.WithLabelValues("target_to_client").Add(float64(n))
	}()

	wg.Wait()
	closeBoth()
	<-doneCancelWatch
}

// copyWithIdle is io.Copy with a per-read idle deadline. When idle == 0
// the read deadline is not changed. The function returns the bytes
// transferred and any non-EOF error.
func copyWithIdle(dst io.Writer, src net.Conn, idle time.Duration) (int64, error) {
	const bufSize = 32 * 1024
	buf := make([]byte, bufSize)
	var total int64
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return total, nil
			}
			return total, er
		}
	}
}

// mapDialError translates a Go net error into the closest SOCKS5 reply code
// per RFC 1928 §6. Context errors are checked first because DialContext can
// return them un-wrapped in *net.OpError on some platforms.
func mapDialError(err error) byte {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return repTTLExpired
	case errors.Is(err, context.Canceled):
		return repServerFailure
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return repTTLExpired
		}
		// errno-style mapping is platform-specific; default to host unreachable.
		return repHostUnreachable
	}
	return repServerFailure
}

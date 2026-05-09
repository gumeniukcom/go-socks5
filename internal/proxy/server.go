package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gumeniukcom/go-socks5/internal/metrics"
)

// Options configures a Server. Most fields are required and validated by
// NewServer. IdleTimeout may be zero to disable per-read deadlines on the
// data-transfer phase. ShutdownTimeout caps how long Serve will wait for
// in-flight tunnels to drain after ctx is cancelled; zero means wait forever.
type Options struct {
	Auth             Authorizer
	Logger           *slog.Logger
	Metrics          *metrics.Metrics
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
	IdleTimeout      time.Duration
	ShutdownTimeout  time.Duration
	MaxConns         int
}

// Server runs a SOCKS5 proxy on a single listener.
type Server struct {
	opts Options
}

// NewServer validates opts and returns a ready-to-run Server.
func NewServer(opts Options) (*Server, error) {
	if opts.Auth == nil {
		return nil, errors.New("server: Auth is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("server: Logger is required")
	}
	if opts.Metrics == nil {
		return nil, errors.New("server: Metrics is required")
	}
	if opts.HandshakeTimeout <= 0 {
		return nil, errors.New("server: HandshakeTimeout must be > 0")
	}
	if opts.DialTimeout <= 0 {
		return nil, errors.New("server: DialTimeout must be > 0")
	}
	if opts.IdleTimeout < 0 {
		return nil, errors.New("server: IdleTimeout must be >= 0")
	}
	if opts.ShutdownTimeout < 0 {
		return nil, errors.New("server: ShutdownTimeout must be >= 0")
	}
	if opts.MaxConns <= 0 {
		return nil, errors.New("server: MaxConns must be > 0")
	}
	return &Server{opts: opts}, nil
}

// ListenAndServe binds network/address then calls Serve. ctx cancellation
// triggers a graceful shutdown: stop accepting, drain in-flight connections,
// then return.
func (s *Server) ListenAndServe(ctx context.Context, network, address string) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts on ln until ctx is cancelled or ln returns a permanent
// error. ln is closed on return.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.opts.Logger.Info("serving",
		"address", ln.Addr().String(),
		"max_conns", s.opts.MaxConns,
		"auth", s.opts.Auth.ShouldAuth(),
	)

	// On cancel, close the listener so Accept returns immediately.
	closerDone := make(chan struct{})
	go func() {
		defer close(closerDone)
		<-ctx.Done()
		_ = ln.Close()
	}()
	defer func() {
		// Ensure the closer goroutine exits if we return for non-cancel reasons.
		_ = ln.Close()
		<-closerDone
	}()

	sema := make(chan struct{}, s.opts.MaxConns)
	var wg sync.WaitGroup

	// waitWithTimeout drains in-flight connection goroutines but bounds the
	// wait by ShutdownTimeout. The inner goroutine completes once all
	// connections respect ctx cancellation (they all do; see connection.go).
	// If a stuck connection prevents wg.Wait from returning, the timer
	// fires and Serve returns; the inner goroutine then continues only
	// until the parent process exits. Process supervisors enforce the
	// upper bound (typically SIGKILL after a grace period).
	waitWithTimeout := func() {
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		if s.opts.ShutdownTimeout <= 0 {
			<-done
			return
		}
		select {
		case <-done:
		case <-time.After(s.opts.ShutdownTimeout):
			s.opts.Logger.Warn("shutdown timeout reached; forcing exit",
				"timeout", s.opts.ShutdownTimeout)
		}
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				waitWithTimeout()
				return nil
			}
			// Listener may be in a transient bad state; surface it.
			waitWithTimeout()
			return err
		}

		// Acquire connection slot or shed load on context cancellation.
		select {
		case sema <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			waitWithTimeout()
			return nil
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sema }()
			defer func() {
				if r := recover(); r != nil {
					s.opts.Logger.Error("connection panic",
						"remote", c.RemoteAddr(),
						"panic", r,
					)
					_ = c.Close()
				}
			}()
			s.opts.Metrics.TotalConnections.Inc()
			s.opts.Metrics.ActiveConnections.Inc()
			defer s.opts.Metrics.ActiveConnections.Dec()

			(&connection{
				conn:             c,
				auth:             s.opts.Auth,
				logger:           s.opts.Logger,
				metrics:          s.opts.Metrics,
				handshakeTimeout: s.opts.HandshakeTimeout,
				dialTimeout:      s.opts.DialTimeout,
				idleTimeout:      s.opts.IdleTimeout,
			}).serve(ctx)
		}(conn)
	}
}

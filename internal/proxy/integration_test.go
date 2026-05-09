package proxy_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gumeniukcom/go-socks5/internal/metrics"
	"github.com/gumeniukcom/go-socks5/internal/proxy"
)

func newTestServer(t *testing.T, auth proxy.Authorizer) (string, context.CancelFunc) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := proxy.NewServer(proxy.Options{
		Auth:             auth,
		Logger:           logger,
		Metrics:          metrics.NoOp(),
		HandshakeTimeout: 5 * time.Second,
		DialTimeout:      5 * time.Second,
		IdleTimeout:      5 * time.Second,
		MaxConns:         16,
	})
	if err != nil {
		t.Fatal(err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return addr, cancel
}

// proxyGet performs an HTTP GET through the SOCKS5 proxy and returns the
// response body. It centralises the noctx/bodyclose plumbing so individual
// tests stay focused on assertions.
func proxyGet(t *testing.T, proxyAddr, target string, userInfo *url.Userinfo) ([]byte, error) {
	t.Helper()
	proxyURL := &url.URL{Scheme: "socks5", Host: proxyAddr, User: userInfo}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

func TestProxyConnectNoAuth(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(upstream.Close)

	addr, _ := newTestServer(t, proxy.NoAuth{})

	body, err := proxyGet(t, addr, upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q", body)
	}
}

func TestProxyConnectWithAuth(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	hash, err := proxy.HashPassword([]byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := proxy.NewArgonAuth(true, map[string]string{"alice": hash})
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := newTestServer(t, auth)

	t.Run("good creds", func(t *testing.T) {
		b, err := proxyGet(t, addr, upstream.URL, url.UserPassword("alice", "hunter2"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "ok" {
			t.Fatalf("body = %q", b)
		}
	})

	t.Run("bad creds rejected", func(t *testing.T) {
		_, err := proxyGet(t, addr, upstream.URL, url.UserPassword("alice", "nope"))
		if err == nil {
			t.Fatal("expected auth failure to surface as error")
		}
	})
}

func TestProxyShutdown(t *testing.T) {
	t.Parallel()
	addr, cancel := newTestServer(t, proxy.NoAuth{})

	// Establish a TCP connection so something is in flight.
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cancel() // Trigger shutdown.

	// New connection should fail soon after.
	probeDialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := probeDialer.DialContext(context.Background(), "tcp", addr)
		if derr != nil {
			return
		}
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server still accepting connections after cancel")
}

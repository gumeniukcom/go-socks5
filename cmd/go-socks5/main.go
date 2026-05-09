// go-socks5 is a SOCKS5 proxy server. See README.md for configuration.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // gated behind --pprof-addr flag
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gumeniukcom/go-socks5/internal/config"
	"github.com/gumeniukcom/go-socks5/internal/metrics"
	"github.com/gumeniukcom/go-socks5/internal/proxy"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("c", "config.toml", "path to TOML config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("go-socks5 %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" || s.Key == "vcs.time" {
					fmt.Printf("%s=%s\n", s.Key, s.Value)
				}
			}
		}
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	logger := newLogger(cfg.LogFormat, cfg.LogLevel)
	logger.Info("starting", "version", version, "listen", cfg.Listen, "auth", cfg.AuthEnable)

	auth, err := buildAuthorizer(cfg)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	m.SetBuildInfo(version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	srv, err := proxy.NewServer(proxy.Options{
		Auth:             auth,
		Logger:           logger,
		Metrics:          m,
		HandshakeTimeout: cfg.HandshakeTimeout,
		DialTimeout:      cfg.DialTimeout,
		IdleTimeout:      cfg.IdleTimeout,
		ShutdownTimeout:  cfg.ShutdownTimeout,
		MaxConns:         cfg.MaxConns,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Optional: metrics + /healthz endpoint on the same sidecar.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	stopMetrics := startSidecar(ctx, logger, "metrics", cfg.MetricsAddr, mux)
	defer stopMetrics()

	// Optional: pprof endpoint.
	stopPProf := startSidecar(ctx, logger, "pprof", cfg.PProfAddr, http.DefaultServeMux)
	defer stopPProf()

	logger.Info("ready")
	if err := srv.ListenAndServe(ctx, "tcp", cfg.Listen); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

func newLogger(format, level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func buildAuthorizer(cfg config.Config) (proxy.Authorizer, error) {
	if !cfg.AuthEnable {
		return proxy.NoAuth{}, nil
	}
	users := make(map[string]string, len(cfg.Users))
	for _, u := range cfg.Users {
		users[u.Login] = u.Pass
	}
	return proxy.NewArgonAuth(true, users)
}

// startSidecar runs a small HTTP server on addr if addr is non-empty. It
// returns a stop function the caller must call (idempotent). Both the stop
// function and the ctx-cancel goroutine call srv.Shutdown so the graceful
// 5-second window is preserved on either path.
func startSidecar(ctx context.Context, logger *slog.Logger, name, addr string, handler http.Handler) func() {
	if addr == "" {
		return func() {}
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("sidecar listening", "name", name, "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("sidecar failed", "name", name, "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}
}

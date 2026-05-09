// Package config loads and validates go-socks5 runtime configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level runtime configuration loaded from TOML and
// optionally overridden by environment variables.
type Config struct {
	Listen           string        `toml:"listen"`
	AuthEnable       bool          `toml:"auth"`
	Users            []User        `toml:"users"`
	MaxConns         int           `toml:"max_conns"`
	HandshakeTimeout time.Duration `toml:"handshake_timeout"`
	DialTimeout      time.Duration `toml:"dial_timeout"`
	IdleTimeout      time.Duration `toml:"idle_timeout"`
	ShutdownTimeout  time.Duration `toml:"shutdown_timeout"`
	MetricsAddr      string        `toml:"metrics_addr"`
	PProfAddr        string        `toml:"pprof_addr"`
	LogFormat        string        `toml:"log_format"`
	LogLevel         string        `toml:"log_level"`
}

// User represents one credential entry. Password is a PHC argon2id string
// (e.g. "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>").
type User struct {
	Login string `toml:"login"`
	Pass  string `toml:"pass"`
}

// Default returns a Config populated with safe defaults.
func Default() Config {
	return Config{
		Listen:           "0.0.0.0:8008",
		AuthEnable:       false,
		MaxConns:         1024,
		HandshakeTimeout: 30 * time.Second,
		DialTimeout:      10 * time.Second,
		IdleTimeout:      5 * time.Minute,
		ShutdownTimeout:  30 * time.Second,
		LogFormat:        "json",
		LogLevel:         "info",
	}
}

// Load reads TOML from path, applies env overrides, and validates the result.
// Env overrides:
//
//	SOCKS5_LISTEN, SOCKS5_AUTH (true/false), SOCKS5_MAX_CONNS,
//	SOCKS5_METRICS_ADDR, SOCKS5_PPROF_ADDR,
//	SOCKS5_LOG_FORMAT, SOCKS5_LOG_LEVEL.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		if _, err := toml.DecodeFile(path, &cfg); err != nil {
			return Config{}, fmt.Errorf("config: decode %q: %w", path, err)
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SOCKS5_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("SOCKS5_AUTH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AuthEnable = b
		}
	}
	if v := os.Getenv("SOCKS5_MAX_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxConns = n
		}
	}
	if v := os.Getenv("SOCKS5_METRICS_ADDR"); v != "" {
		cfg.MetricsAddr = v
	}
	if v := os.Getenv("SOCKS5_PPROF_ADDR"); v != "" {
		cfg.PProfAddr = v
	}
	if v := os.Getenv("SOCKS5_LOG_FORMAT"); v != "" {
		cfg.LogFormat = v
	}
	if v := os.Getenv("SOCKS5_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

// Validate returns an error describing the first invalid field.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("config: listen must not be empty")
	}
	if _, err := net.ResolveTCPAddr("tcp", c.Listen); err != nil {
		return fmt.Errorf("config: invalid listen address %q: %w", c.Listen, err)
	}
	if c.AuthEnable && len(c.Users) == 0 {
		return errors.New("config: auth enabled but no users configured")
	}
	if !c.AuthEnable && len(c.Users) > 0 {
		return errors.New("config: users configured but auth disabled (set auth = true)")
	}
	seen := make(map[string]struct{}, len(c.Users))
	for i, u := range c.Users {
		if u.Login == "" {
			return fmt.Errorf("config: users[%d]: login must not be empty", i)
		}
		if u.Pass == "" {
			return fmt.Errorf("config: users[%d]: pass must not be empty", i)
		}
		if _, dup := seen[u.Login]; dup {
			return fmt.Errorf("config: duplicate login %q", u.Login)
		}
		seen[u.Login] = struct{}{}
	}
	if c.MaxConns <= 0 {
		return errors.New("config: max_conns must be > 0")
	}
	if c.HandshakeTimeout <= 0 {
		return errors.New("config: handshake_timeout must be > 0")
	}
	if c.DialTimeout <= 0 {
		return errors.New("config: dial_timeout must be > 0")
	}
	if c.IdleTimeout < 0 {
		return errors.New("config: idle_timeout must be >= 0")
	}
	if c.ShutdownTimeout < 0 {
		return errors.New("config: shutdown_timeout must be >= 0")
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		return fmt.Errorf("config: log_format must be json or text, got %q", c.LogFormat)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level must be debug|info|warn|error, got %q", c.LogLevel)
	}
	if c.MetricsAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.MetricsAddr); err != nil {
			return fmt.Errorf("config: invalid metrics_addr %q: %w", c.MetricsAddr, err)
		}
	}
	if c.PProfAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.PProfAddr); err != nil {
			return fmt.Errorf("config: invalid pprof_addr %q: %w", c.PProfAddr, err)
		}
	}
	return nil
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "default ok", mutate: func(c *Config) {}},
		{
			name:    "empty listen",
			mutate:  func(c *Config) { c.Listen = "" },
			wantErr: "listen must not be empty",
		},
		{
			name:    "bad listen",
			mutate:  func(c *Config) { c.Listen = "not:a:valid:addr" },
			wantErr: "invalid listen address",
		},
		{
			name:    "auth enabled no users",
			mutate:  func(c *Config) { c.AuthEnable = true },
			wantErr: "no users configured",
		},
		{
			name: "users without auth",
			mutate: func(c *Config) {
				c.Users = []User{{Login: "x", Pass: "y"}}
			},
			wantErr: "auth disabled",
		},
		{
			name: "duplicate login",
			mutate: func(c *Config) {
				c.AuthEnable = true
				c.Users = []User{
					{Login: "a", Pass: "x"},
					{Login: "a", Pass: "y"},
				}
			},
			wantErr: "duplicate login",
		},
		{
			name:    "max conns zero",
			mutate:  func(c *Config) { c.MaxConns = 0 },
			wantErr: "max_conns",
		},
		{
			name:    "bad log format",
			mutate:  func(c *Config) { c.LogFormat = "xml" },
			wantErr: "log_format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	if err := os.WriteFile(path, []byte(`listen = "127.0.0.1:1080"`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOCKS5_LISTEN", "127.0.0.1:9999")
	t.Setenv("SOCKS5_MAX_CONNS", "42")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Fatalf("env override missed: %q", cfg.Listen)
	}
	if cfg.MaxConns != 42 {
		t.Fatalf("max_conns env: %d", cfg.MaxConns)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Package config loads Turnstile's configuration from environment variables,
// seeded from an optional .env file in the working directory (real environment
// variables always take precedence). Every value is optional with a sane
// default.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// defaultAuditRetentionDays is how long audit entries are kept when
// AUDIT_RETENTION_DAYS is unset. One year balances useful history against
// unbounded growth.
const defaultAuditRetentionDays = 365

// Config holds all runtime configuration.
type Config struct {
	// ListenAddr is the address the Connect/HTTP server binds.
	ListenAddr string
	// DBPath is the SQLite database file path.
	DBPath string
	// AuditRetentionDays is how many days of audit log to keep. 0 disables
	// pruning (keep forever).
	AuditRetentionDays int

	// ServiceCredential, when set, is required in the Authorization: Bearer
	// metadata of Check/Authenticate/ReportAudit calls — the "service
	// credential in metadata" host→Turnstile auth option. Empty leaves those
	// RPCs open (rely on network isolation or mTLS instead).
	ServiceCredential string

	// TLS: when TLSCertFile and TLSKeyFile are both set, the server serves
	// HTTPS. When TLSClientCAFile is also set, client certificates are required
	// and verified against it (mTLS) — the "mTLS" host→Turnstile auth option.
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string
}

// envFile is the optional dotenv file loaded on startup. Real environment
// variables always take precedence over its contents.
const envFile = ".env"

// Load reads configuration from .env (if present) and the environment.
func Load() (*Config, error) {
	if err := LoadDotEnv(envFile); err != nil {
		return nil, err
	}

	cfg := &Config{
		ListenAddr:        envOrDefault("LISTEN_ADDR", ":8080"),
		DBPath:            envOrDefault("DB_PATH", "turnstile.db"),
		ServiceCredential: os.Getenv("SERVICE_CREDENTIAL"),
		TLSCertFile:       os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("TLS_KEY_FILE"),
		TLSClientCAFile:   os.Getenv("TLS_CLIENT_CA_FILE"),
	}

	retention, err := intEnvOrDefault("AUDIT_RETENTION_DAYS", defaultAuditRetentionDays)
	if err != nil {
		return nil, err
	}
	cfg.AuditRetentionDays = retention

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	if cfg.TLSClientCAFile != "" && cfg.TLSCertFile == "" {
		return nil, fmt.Errorf("TLS_CLIENT_CA_FILE requires TLS_CERT_FILE and TLS_KEY_FILE (mTLS needs a server cert)")
	}

	return cfg, nil
}

// TLSEnabled reports whether the server should serve HTTPS.
func (c *Config) TLSEnabled() bool { return c.TLSCertFile != "" && c.TLSKeyFile != "" }

// MutualTLS reports whether client certificates are required (mTLS).
func (c *Config) MutualTLS() bool { return c.TLSEnabled() && c.TLSClientCAFile != "" }

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// intEnvOrDefault parses a non-negative integer env var, returning fallback
// when unset. A malformed or negative value is an error.
func intEnvOrDefault(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer, got %q", key, v)
	}
	return n, nil
}

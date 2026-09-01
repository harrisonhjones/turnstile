package config

import (
	"strings"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Ensure no ambient overrides leak in.
	for _, k := range []string{"LISTEN_ADDR", "DB_PATH", "AUDIT_RETENTION_DAYS", "TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE", "TLS_REQUIRED", "MTLS_REQUIRED"} {
		t.Setenv(k, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TLSRequired || cfg.MTLSRequired {
		t.Errorf("TLS_REQUIRED/MTLS_REQUIRED should default to false, got %+v", cfg)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr default = %q", cfg.ListenAddr)
	}
	if cfg.DBPath != "turnstile.db" {
		t.Errorf("DBPath default = %q", cfg.DBPath)
	}
	if cfg.AuditRetentionDays != defaultAuditRetentionDays {
		t.Errorf("AuditRetentionDays default = %d", cfg.AuditRetentionDays)
	}
	if cfg.TLSEnabled() || cfg.MutualTLS() {
		t.Errorf("TLS should be disabled by default")
	}
}

func TestLoadAuditRetention(t *testing.T) {
	t.Setenv("AUDIT_RETENTION_DAYS", "30")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AuditRetentionDays != 30 {
		t.Errorf("got %d, want 30", cfg.AuditRetentionDays)
	}

	t.Setenv("AUDIT_RETENTION_DAYS", "-5")
	if _, err := Load(); err == nil {
		t.Error("expected error for negative retention")
	}
}

func TestTLSPairing(t *testing.T) {
	// Cert without key is an error.
	t.Setenv("TLS_CERT_FILE", "cert.pem")
	t.Setenv("TLS_KEY_FILE", "")
	if _, err := Load(); err == nil {
		t.Error("expected error when only TLS_CERT_FILE is set")
	}

	// Client CA without a server cert/key is an error.
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_CLIENT_CA_FILE", "ca.pem")
	if _, err := Load(); err == nil {
		t.Error("expected error when TLS_CLIENT_CA_FILE is set without server cert/key")
	}
}

func TestTLSRequired(t *testing.T) {
	for _, k := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE", "MTLS_REQUIRED"} {
		t.Setenv(k, "")
	}

	// TLS_REQUIRED without TLS configured must fail startup.
	t.Setenv("TLS_REQUIRED", "true")
	if _, err := Load(); err == nil {
		t.Error("expected error when TLS_REQUIRED is set but TLS is not configured")
	}

	// With a server cert/key it loads.
	t.Setenv("TLS_CERT_FILE", "cert.pem")
	t.Setenv("TLS_KEY_FILE", "key.pem")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load with TLS configured: %v", err)
	}
	if !cfg.TLSRequired || !cfg.TLSEnabled() {
		t.Errorf("expected TLSRequired and TLSEnabled, got %+v", cfg)
	}
}

// TestTLSRequiredExplicitFalse: an explicit =false disables the guard, so the
// server loads with no cert configured (complements the unset default in
// TestLoadDefaults).
func TestTLSRequiredExplicitFalse(t *testing.T) {
	for _, k := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("TLS_REQUIRED", "false")
	t.Setenv("MTLS_REQUIRED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load with guards explicitly false: %v", err)
	}
	if cfg.TLSRequired || cfg.MTLSRequired {
		t.Errorf("explicit =false should disable the guards, got %+v", cfg)
	}
}

func TestMTLSRequired(t *testing.T) {
	for _, k := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE", "TLS_REQUIRED"} {
		t.Setenv(k, "")
	}

	// MTLS_REQUIRED with no TLS configured must fail startup.
	t.Setenv("MTLS_REQUIRED", "true")
	if _, err := Load(); err == nil {
		t.Error("expected error when MTLS_REQUIRED is set but no TLS is configured")
	}

	// Server cert/key but no client CA is still not mutual TLS → error.
	t.Setenv("TLS_CERT_FILE", "cert.pem")
	t.Setenv("TLS_KEY_FILE", "key.pem")
	if _, err := Load(); err == nil {
		t.Error("expected error when MTLS_REQUIRED is set but TLS_CLIENT_CA_FILE is missing")
	}

	// Full mTLS loads, with both required flags reported set.
	t.Setenv("TLS_CLIENT_CA_FILE", "ca.pem")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load with mTLS configured: %v", err)
	}
	if !cfg.MTLSRequired || !cfg.MutualTLS() {
		t.Errorf("expected MTLSRequired and MutualTLS, got %+v", cfg)
	}
}

// TestMTLSRequiredWithTLSRequired: with both flags set, MTLS_REQUIRED subsumes
// TLS_REQUIRED — nothing configured surfaces the single (mTLS) error, and full
// mTLS satisfies both.
func TestMTLSRequiredWithTLSRequired(t *testing.T) {
	for _, k := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("TLS_REQUIRED", "true")
	t.Setenv("MTLS_REQUIRED", "true")

	// Nothing configured: the reported error is the mTLS one, not the weaker TLS one.
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when both guards are set but nothing is configured")
	}
	if !strings.Contains(err.Error(), "MTLS_REQUIRED") {
		t.Errorf("expected the mTLS error to take precedence, got %q", err.Error())
	}

	// Full mTLS satisfies both flags.
	t.Setenv("TLS_CERT_FILE", "cert.pem")
	t.Setenv("TLS_KEY_FILE", "key.pem")
	t.Setenv("TLS_CLIENT_CA_FILE", "ca.pem")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load with full mTLS and both flags set: %v", err)
	}
	if !cfg.TLSRequired || !cfg.MTLSRequired || !cfg.MutualTLS() {
		t.Errorf("expected both flags and MutualTLS, got %+v", cfg)
	}
}

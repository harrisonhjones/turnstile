package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	// Ensure no ambient overrides leak in.
	for _, k := range []string{"LISTEN_ADDR", "DB_PATH", "AUDIT_RETENTION_DAYS", "TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE"} {
		t.Setenv(k, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
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
	for _, k := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_CLIENT_CA_FILE"} {
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

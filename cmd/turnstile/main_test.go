package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"harrisonhjones.com/turnstile/internal/config"
)

func TestBuildTLSConfig(t *testing.T) {
	// TLS disabled → nil config, no error.
	tc, err := buildTLSConfig(&config.Config{})
	if err != nil {
		t.Fatalf("disabled: %v", err)
	}
	if tc != nil {
		t.Errorf("disabled: expected nil tls.Config, got %+v", tc)
	}

	// TLS without mTLS → config with no client-cert requirement.
	tc, err = buildTLSConfig(&config.Config{TLSCertFile: "cert.pem", TLSKeyFile: "key.pem"})
	if err != nil {
		t.Fatalf("tls-only: %v", err)
	}
	if tc == nil || tc.ClientAuth != tls.NoClientCert {
		t.Errorf("tls-only: expected NoClientCert, got %+v", tc)
	}

	// mTLS with a valid client CA → require + verify client certs.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, makeCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	tc, err = buildTLSConfig(&config.Config{TLSCertFile: "cert.pem", TLSKeyFile: "key.pem", TLSClientCAFile: caFile})
	if err != nil {
		t.Fatalf("mtls: %v", err)
	}
	if tc.ClientAuth != tls.RequireAndVerifyClientCert || tc.ClientCAs == nil {
		t.Errorf("mtls: expected RequireAndVerifyClientCert with a client CA pool, got %+v", tc)
	}

	// mTLS with a CA file containing no certificates → error.
	badFile := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildTLSConfig(&config.Config{TLSCertFile: "cert.pem", TLSKeyFile: "key.pem", TLSClientCAFile: badFile}); err == nil {
		t.Error("expected an error for a client CA file with no certificates")
	}
}

// makeCAPEM returns a self-signed CA certificate in PEM form for use as a
// client-CA trust anchor in the mTLS test.
func makeCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "turnstile-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

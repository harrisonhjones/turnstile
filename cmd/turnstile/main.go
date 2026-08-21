package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/harrisonhjones/turnstile/internal/audit"
	"github.com/harrisonhjones/turnstile/internal/config"
	"github.com/harrisonhjones/turnstile/internal/management"
	"github.com/harrisonhjones/turnstile/internal/ratelimit"
	"github.com/harrisonhjones/turnstile/internal/server"
	"github.com/harrisonhjones/turnstile/internal/store"
	"github.com/harrisonhjones/turnstile/internal/token"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()

	// First-run bootstrap: seed a default policy and an admin credential, and
	// print the admin token once. Deleting all admin credentials re-seeds here.
	adminToken, err := token.BootstrapIfEmpty(ctx, db, time.Now())
	if err != nil {
		return err
	}
	if adminToken != "" {
		slog.Warn("created bootstrap admin credential — store this token now, it will not be shown again",
			"admin_token", adminToken)
	}

	// Load the global policy into an in-memory cache for fast authorization.
	gp, err := db.GetGlobalPolicy(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	policyCache := token.NewPolicyCache(gp)

	// Rate limiter, seeded from the global policy's configured limits. Kept in
	// sync by UpdatePolicy; per-key limiters dropped on key delete.
	var rlGlobal ratelimit.Global
	if gp != nil {
		rlGlobal = gp.Constraints.RateLimits
	}
	rateLimiter := ratelimit.New(rlGlobal)

	authenticator := token.NewAuthenticator(db)
	authorizer := token.NewAuthorizer(policyCache)
	auditWriter := audit.NewWriter(db)

	// Background maintenance loops, cancelled on shutdown:
	//   - prune audit entries older than the retention window,
	//   - evict idle rate limiters so the manager's maps don't grow unbounded.
	bgCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	go audit.RunRetention(bgCtx, db, cfg.AuditRetentionDays, time.Now)
	go rateLimiter.RunEviction(bgCtx, 10*time.Minute)

	svc := server.New(server.Deps{
		Store:             db,
		Authenticator:     authenticator,
		Authorizer:        authorizer,
		PolicyCache:       policyCache,
		RateLimiter:       rateLimiter,
		AuditWriter:       auditWriter,
		ServiceCredential: cfg.ServiceCredential,
	})

	// Gate that makes graceful shutdown drain in-flight requests correctly even
	// on the hijacked-connection h2c path (see ShutdownGate).
	gate := server.NewShutdownGate()

	mux := http.NewServeMux()

	// The Connect service (gRPC, gRPC-Web, and Connect HTTP/JSON on one route).
	svcPath, svcHandler := svc.NewConnectHandler(connect.WithInterceptors(gate))
	mux.Handle(svcPath, svcHandler)

	// Unauthenticated health check.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Management web UI at /ui/, plus a root redirect to it.
	uiHandler, err := management.Handler()
	if err != nil {
		return err
	}
	mux.Handle("/ui/", uiHandler)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return err
	}

	// Without TLS, wrap in h2c so the gRPC hot path (which needs HTTP/2) works
	// over plaintext. With TLS, HTTP/2 is negotiated via ALPN.
	var handler http.Handler = mux
	if tlsConfig == nil {
		handler = h2c.NewHandler(mux, &http2.Server{})
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("starting server", "addr", cfg.ListenAddr, "tls", cfg.TLSEnabled(), "mtls", cfg.MutualTLS(),
			"service_credential_required", cfg.ServiceCredential != "")
		var serveError error
		if cfg.TLSEnabled() {
			serveError = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveError = srv.ListenAndServe()
		}
		if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
			serveErr <- serveError
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		return err
	case <-quit:
	}

	slog.Info("shutting down server")
	stopBackground() // stop retention + limiter-eviction loops

	// Stop accepting new RPCs, cancel in-flight handler contexts, and wait
	// (bounded) for them to drain. This works on both the TLS and the hijacked
	// h2c paths, unlike http.Server.Shutdown alone, which does not track h2c
	// connections. A stuck/hostile stream can't hang us — the wait is bounded.
	if !gate.Quiesce(8 * time.Second) {
		slog.Warn("shutdown: some in-flight requests did not drain before the deadline; proceeding")
	}

	// Now stop the listener and close idle tracked connections.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}
	// Handlers have drained (or the deadline elapsed), so no new audit writes or
	// background last-used writes will be launched. Drain both before the
	// deferred db.Close, so in-flight writes aren't lost to a closing DB.
	auditWriter.Wait()
	authenticator.Wait()
	return nil
}

// buildTLSConfig returns a *tls.Config when TLS is enabled, requiring and
// verifying client certificates against the configured CA when mTLS is on.
// Returns nil (plaintext) when TLS is not configured.
func buildTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if !cfg.TLSEnabled() {
		return nil, nil
	}
	// The server cert/key are loaded by ListenAndServeTLS; here we only add the
	// client-CA trust store and require client certs when mTLS is enabled.
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.MutualTLS() {
		pem, err := os.ReadFile(cfg.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA file %q contained no certificates", cfg.TLSClientCAFile)
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

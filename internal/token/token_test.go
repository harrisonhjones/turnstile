package token

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestGenerateAndHash(t *testing.T) {
	tok, hash, err := Generate(APIKeyPrefix)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(tok, APIKeyPrefix) {
		t.Errorf("token missing prefix: %q", tok)
	}
	if Hash(tok) != hash {
		t.Errorf("Hash(token) != returned hash")
	}
	if hash == tok {
		t.Errorf("hash should differ from plaintext")
	}
	// Distinct calls produce distinct tokens.
	tok2, _, _ := Generate(APIKeyPrefix)
	if tok == tok2 {
		t.Errorf("expected unique tokens")
	}
}

func TestExtractBearer(t *testing.T) {
	tests := map[string]string{
		"Bearer abc123":  "abc123",
		"bearer abc123":  "abc123", // case-insensitive scheme
		"Bearer  spaced": "spaced",
		"Basic abc":      "",
		"":               "",
		"abc123":         "",
	}
	for in, want := range tests {
		if got := ExtractBearer(in); got != want {
			t.Errorf("ExtractBearer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	tok, hash, _ := Generate(APIKeyPrefix)
	expiredAt := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// Active key.
	if err := s.CreateAPIKey(ctx, &store.APIKey{ID: "k1", Name: "active", KeyHash: hash, CreatedAt: now, ExpiresAt: &future,
		Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{"*"}}}}); err != nil {
		t.Fatal(err)
	}
	// Disabled key.
	dtok, dhash, _ := Generate(APIKeyPrefix)
	s.CreateAPIKey(ctx, &store.APIKey{ID: "k2", Name: "disabled", KeyHash: dhash, CreatedAt: now, Disabled: true,
		Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{"*"}}}})
	// Expired key.
	etok, ehash, _ := Generate(APIKeyPrefix)
	s.CreateAPIKey(ctx, &store.APIKey{ID: "k3", Name: "expired", KeyHash: ehash, CreatedAt: now, ExpiresAt: &expiredAt,
		Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"*"}, Resources: []string{"*"}}}})

	a := NewAuthenticator(s)

	if _, err := a.Authenticate(ctx, ""); !errors.Is(err, ErrMissingToken) {
		t.Errorf("empty token: got %v, want ErrMissingToken", err)
	}
	if _, err := a.Authenticate(ctx, "tsk_nope"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unknown token: got %v, want ErrInvalidToken", err)
	}
	if _, err := a.Authenticate(ctx, dtok); !errors.Is(err, ErrKeyDisabled) {
		t.Errorf("disabled: got %v, want ErrKeyDisabled", err)
	}
	if _, err := a.Authenticate(ctx, etok); !errors.Is(err, ErrKeyExpired) {
		t.Errorf("expired: got %v, want ErrKeyExpired", err)
	}
	p, err := a.Authenticate(ctx, tok)
	if err != nil {
		t.Fatalf("active key: %v", err)
	}
	if p.Key.ID != "k1" {
		t.Errorf("wrong principal: %+v", p.Key)
	}
}

func TestAuthorizerGlobalCeiling(t *testing.T) {
	// Global policy denies svc:danger everywhere; the cache holds it.
	gp := &store.GlobalPolicy{
		Statements: []policy.Statement{{Effect: policy.Deny, Actions: []string{"svc:danger"}, Resources: []string{"*"}}},
	}
	cache := NewPolicyCache(gp)
	az := NewAuthorizer(cache)

	key := &store.APIKey{
		ID: "k1",
		Statements: []policy.Statement{
			{Effect: policy.Allow, Actions: []string{"svc:*"}, Resources: []string{"*"}},
		},
	}

	// A benign action the key allows.
	if !az.Authorize(key, "svc:read", "svc:thing:1").Allowed {
		t.Error("svc:read should be allowed by the key")
	}
	// The key allows svc:danger, but the global deny ceiling overrides it.
	if az.Authorize(key, "svc:danger", "svc:thing:1").Allowed {
		t.Error("svc:danger must be denied by the global ceiling despite the key's allow")
	}
	// nil key is denied.
	if az.Authorize(nil, "svc:read").Allowed {
		t.Error("nil key must be denied")
	}

	// Updating the cache to an empty policy lifts the ceiling.
	cache.Set(&store.GlobalPolicy{})
	if !az.Authorize(key, "svc:danger", "svc:thing:1").Allowed {
		t.Error("after lifting the ceiling, svc:danger should be allowed by the key")
	}
}

// TestShouldTouchDebounce verifies the process-global last-used debounce: at
// most one write per subject per interval, independent across subjects.
func TestShouldTouchDebounce(t *testing.T) {
	a := NewAuthenticator(nil) // shouldTouch doesn't touch the store
	base := time.Now()

	if !a.shouldTouch("k:1", base) {
		t.Fatal("first touch should proceed")
	}
	if a.shouldTouch("k:1", base.Add(30*time.Second)) {
		t.Error("a second touch within the interval should be skipped (debounced)")
	}
	if !a.shouldTouch("k:1", base.Add(2*touchInterval)) {
		t.Error("a touch after the interval should proceed")
	}
	// A different subject debounces independently.
	if !a.shouldTouch("k:2", base.Add(30*time.Second)) {
		t.Error("a different subject should not be debounced by the first")
	}
}

func TestBootstrapIfEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now()

	tok, err := BootstrapIfEmpty(ctx, s, now)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if !strings.HasPrefix(tok, APIKeyPrefix) {
		t.Errorf("bootstrap should return an API key token, got %q", tok)
	}
	// The bootstrap key authenticates and carries full management access.
	a := NewAuthenticator(s)
	principal, err := a.Authenticate(ctx, tok)
	if err != nil {
		t.Fatalf("bootstrap token should authenticate: %v", err)
	}
	az := NewAuthorizer(NewPolicyCache(nil))
	if !az.AuthorizeManagement(principal.Key, "turnstile:create-key", "*").Allowed {
		t.Error("bootstrap key should allow turnstile:create-key")
	}
	// A default global policy was seeded.
	if _, err := s.GetGlobalPolicy(ctx); err != nil {
		t.Errorf("expected a seeded global policy: %v", err)
	}
	// Idempotent: a second call with keys already present returns no new token.
	tok2, err := BootstrapIfEmpty(ctx, s, now)
	if err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if tok2 != "" {
		t.Errorf("second bootstrap should not re-seed, got token %q", tok2)
	}
	// Exactly one key was seeded (the full-admin bootstrap key).
	if n, _ := s.CountAPIKeys(ctx); n != 1 {
		t.Errorf("bootstrap should seed exactly one key, got %d", n)
	}
}

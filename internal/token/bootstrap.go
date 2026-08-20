package token

import (
	"context"
	"fmt"
	"time"

	"github.com/harrisonhjones/turnstile/internal/policy"
	"github.com/harrisonhjones/turnstile/internal/ratelimit"
	"github.com/harrisonhjones/turnstile/internal/store"
)

// BootstrapIfEmpty seeds first-run state:
//
//   - A default global policy (empty deny-only ceiling with sane rate-limit
//     defaults) if none exists yet.
//   - A bootstrap admin credential if the admin_credentials table is empty. Its
//     plaintext is returned so the caller can log it exactly once.
//
// Deleting every admin credential and restarting re-seeds a fresh one: this is
// the intentional lockout-recovery path. Unlike a host's own bootstrap key,
// Turnstile does NOT seed any API keys — client keys are minted by an operator
// through the management API.
func BootstrapIfEmpty(ctx context.Context, s *store.Store, now time.Time) (adminToken string, err error) {
	// Seed a default global policy if none exists.
	if _, gerr := s.GetGlobalPolicy(ctx); gerr == store.ErrNotFound {
		if err := s.UpsertGlobalPolicy(ctx, defaultGlobalPolicy(now)); err != nil {
			return "", fmt.Errorf("seed default policy: %w", err)
		}
	} else if gerr != nil {
		return "", gerr
	}

	count, err := s.CountAdminCredentials(ctx)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}

	plaintext, hash, err := Generate(AdminPrefix)
	if err != nil {
		return "", err
	}
	cred := &store.AdminCredential{
		ID:        NewID("adm"),
		Name:      "bootstrap",
		CredHash:  hash,
		Note:      "Bootstrap admin credential created on first run.",
		CreatedAt: now,
	}
	if err := s.CreateAdminCredential(ctx, cred); err != nil {
		return "", fmt.Errorf("create bootstrap admin credential: %w", err)
	}
	return plaintext, nil
}

// defaultGlobalPolicy returns an empty-but-valid starting policy: no deny
// statements (no restrictions) plus domain-agnostic rate-limit defaults. There
// are no per-action entries because Turnstile knows nothing about any host's
// action vocabulary — operators add them via UpdatePolicy.
func defaultGlobalPolicy(now time.Time) *store.GlobalPolicy {
	return &store.GlobalPolicy{
		Version:    1,
		Statements: []policy.Statement{},
		Constraints: store.Constraints{
			RateLimits: ratelimit.Global{
				// Each key: a generous default across all actions.
				PerKey: ratelimit.Config{
					Default: &ratelimit.Limit{PerMinute: 120},
				},
				// Whole service: caps aggregate throughput across all keys.
				ServiceWide: ratelimit.Config{
					Default: &ratelimit.Limit{PerMinute: 600},
				},
			},
		},
		UpdatedAt: now,
		UpdatedBy: "bootstrap",
	}
}

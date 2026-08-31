package token

import (
	"context"
	"fmt"
	"strings"
	"time"

	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/ratelimit"
	"harrisonhjones.com/turnstile/internal/store"
)

// fullAdminStatements grants every management action on every resource —
// allow turnstile:* on *. This is what makes a key a full admin; it is an
// ordinary key statement, evaluated by the same engine as everything else.
func fullAdminStatements() []policy.Statement {
	return []policy.Statement{{
		Effect:    policy.Allow,
		Actions:   []string{"turnstile:*"},
		Resources: []string{"*"},
		Note:      "full management access",
	}}
}

// BootstrapIfEmpty seeds first-run state:
//
//   - The default global policy (an empty deny-only ceiling with sane rate-limit
//     defaults) if none exists yet.
//   - A full-admin bootstrap key if the api_keys table is empty. Its plaintext
//     token is returned so the caller can log it exactly once.
//
// Management is governed by the same keys and policy engine as everything else,
// so the bootstrap key is just an ordinary key that allows turnstile:* on *. It
// has no special status — it can be rotated or deleted like any other key. If you
// lock yourself out (delete/disable the last admin key), the break-glass path
// (MintAdminKey, via the -bootstrap flag / TURNSTILE_BOOTSTRAP env) mints a fresh
// full-admin key even when keys already exist.
func BootstrapIfEmpty(ctx context.Context, s *store.Store, now time.Time) (token string, err error) {
	// Seed a default global policy if none exists.
	if _, gerr := s.GetGlobalPolicy(ctx); gerr == store.ErrNotFound {
		if err := s.UpsertGlobalPolicy(ctx, defaultGlobalPolicy(now)); err != nil {
			return "", fmt.Errorf("seed default policy: %w", err)
		}
	} else if gerr != nil {
		return "", gerr
	}

	count, err := s.CountAPIKeys(ctx)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	return MintAdminKey(ctx, s, now, "bootstrap")
}

// MintAdminKey creates a new full-admin key (allow turnstile:* on *) and returns
// its plaintext token to log exactly once. It backs both first-run bootstrap and
// break-glass recovery — the latter mints one even when keys already exist. The
// key's name is namePrefix plus a short suffix from its random id, so repeated
// mints never collide on the UNIQUE(name) constraint.
func MintAdminKey(ctx context.Context, s *store.Store, now time.Time, namePrefix string) (string, error) {
	plaintext, hash, err := Generate(APIKeyPrefix)
	if err != nil {
		return "", err
	}
	id := NewID("key")
	// Discriminator from the id's random hex tail (unique per key).
	suffix := id[strings.LastIndex(id, ":")+1:]
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	k := &store.APIKey{
		ID:         id,
		Name:       namePrefix + "-" + suffix,
		KeyHash:    hash,
		Statements: fullAdminStatements(),
		Note:       "Full-admin key created by " + namePrefix + ".",
		CreatedAt:  now,
	}
	if err := s.CreateAPIKey(ctx, k); err != nil {
		return "", fmt.Errorf("create %s key: %w", namePrefix, err)
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

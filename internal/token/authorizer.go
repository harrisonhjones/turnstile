package token

import (
	"github.com/harrisonhjones/turnstile/internal/policy"
	"github.com/harrisonhjones/turnstile/internal/store"
)

// Authorizer evaluates whether an authenticated key may perform an action,
// merging the cached global policy (a deny-only ceiling) beneath the key's own
// statements.
type Authorizer struct {
	cache *PolicyCache
}

func NewAuthorizer(cache *PolicyCache) *Authorizer {
	return &Authorizer{cache: cache}
}

// Authorize decides whether key may perform action on the object identified by
// the given resource representations. A nil key is denied.
//
// Statements are evaluated global-first so a global deny cannot be overridden
// by a key-level allow.
func (az *Authorizer) Authorize(key *store.APIKey, action string, resources ...string) policy.Decision {
	if key == nil {
		return policy.Decision{Allowed: false}
	}
	// Evaluate global-first without merging: no per-request allocation, and the
	// cached global slice is used read-only (see PolicyCache.GlobalStatements).
	return policy.EvaluateLayers(action, resources, az.cache.GlobalStatements(), key.Statements)
}

// GrantsAction reports whether key could ever perform action on some resource,
// merging global policy with the key's statements. It is a coarse,
// resource-independent hint (see policy.GrantsAction) — not an authorization
// decision.
func (az *Authorizer) GrantsAction(key *store.APIKey, action string) bool {
	if key == nil {
		return false
	}
	global := az.cache.GlobalStatements()
	merged := make([]policy.Statement, 0, len(global)+len(key.Statements))
	merged = append(merged, global...)
	merged = append(merged, key.Statements...)
	return policy.GrantsAction(merged, action)
}

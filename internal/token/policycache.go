package token

import (
	"sync"

	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/store"
)

// PolicyCache holds the current global policy in memory so authorization checks
// don't hit the database on every request. It is safe for concurrent use and is
// refreshed whenever the policy is updated.
type PolicyCache struct {
	mu     sync.RWMutex
	global *store.GlobalPolicy
}

// NewPolicyCache creates a cache seeded with the given policy (may be nil, in
// which case only implicit-deny global behavior applies until Set is called).
func NewPolicyCache(gp *store.GlobalPolicy) *PolicyCache {
	return &PolicyCache{global: gp}
}

// Set replaces the cached policy. Called after a policy update.
func (c *PolicyCache) Set(gp *store.GlobalPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.global = gp
}

// GlobalStatements returns the current global statements, or nil if no policy is
// loaded. The returned slice is the cached one and MUST be treated as read-only:
// the cache replaces it wholesale on Set and never mutates it in place, so
// sharing it (rather than copying) avoids an allocation on every authorization.
func (c *PolicyCache) GlobalStatements() []policy.Statement {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.global == nil {
		return nil
	}
	return c.global.Statements
}

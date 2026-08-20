package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Manager enforces per-key and service-wide rate limits. It caches one limiter
// per (key, action) and per action, applying the currently-resolved rate on each
// check so policy edits take effect without a restart. Safe for concurrent use.
type Manager struct {
	mu     sync.Mutex
	global Global
	keyLim map[string]map[string]*rate.Limiter // keyID -> action -> limiter
	svcLim map[string]*rate.Limiter            // action -> limiter
	now    func() time.Time
}

// New builds a Manager with the given global configuration.
func New(g Global) *Manager {
	return &Manager{
		global: g,
		keyLim: make(map[string]map[string]*rate.Limiter),
		svcLim: make(map[string]*rate.Limiter),
		now:    time.Now,
	}
}

// SetGlobal replaces the global configuration (e.g. after a policy update).
// Existing limiters pick up the new rates lazily on their next check.
func (m *Manager) SetGlobal(g Global) {
	m.mu.Lock()
	m.global = g
	m.mu.Unlock()
}

// ForgetKey drops a key's cached limiters (e.g. when the key is deleted).
func (m *Manager) ForgetKey(keyID string) {
	m.mu.Lock()
	delete(m.keyLim, keyID)
	m.mu.Unlock()
}

// EvictIdle drops cached limiters that are at full capacity (i.e. idle: no
// request has consumed a token recently). Recreating a limiter later starts it
// full again, so eviction loses no enforcement state — it just bounds memory on
// a long-lived instance that has seen many (key, action) combinations.
func (m *Manager) EvictIdle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for action, lim := range m.svcLim {
		if isIdle(lim, now) {
			delete(m.svcLim, action)
		}
	}
	for keyID, actions := range m.keyLim {
		for action, lim := range actions {
			if isIdle(lim, now) {
				delete(actions, action)
			}
		}
		if len(actions) == 0 {
			delete(m.keyLim, keyID)
		}
	}
}

// RunEviction evicts idle limiters every interval until ctx is cancelled. A
// non-positive interval disables it and RunEviction returns immediately. Meant
// to run in its own goroutine for the process lifetime.
func (m *Manager) RunEviction(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.EvictIdle()
		}
	}
}

// isIdle reports whether a limiter is back at full capacity as of now (no recent
// consumption), making it safe to drop.
func isIdle(l *rate.Limiter, now time.Time) bool {
	return l.TokensAt(now) >= float64(l.Burst())
}

// Allow reports whether a request by keyID for action is permitted right now. It
// requires BOTH the per-key limiter and the service-wide limiter to allow the
// request; if either would block, neither is charged (the reservations are
// cancelled) and retryAfter is the longer of the two waits.
//
// This is the reserve-then-confirm primitive behind the spec's "denied authz
// never burns rate budget": callers only invoke Allow once authn and authz have
// already passed, and a rate-limit block itself refunds both reservations.
func (m *Manager) Allow(keyID string, keyCfg Config, action string) (ok bool, retryAfter time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	var rk, rs *rate.Reservation

	if l, has := effectiveKey(action, keyCfg, m.global.PerKey); has && !l.unlimited() {
		rk = m.limiter(m.keyActions(keyID), action, l).ReserveN(now, 1)
	}
	if l, has := m.global.ServiceWide.resolve(action); has && !l.unlimited() {
		rs = m.limiter(m.svcLim, action, l).ReserveN(now, 1)
	}

	dk := reservationDelay(rk, now)
	ds := reservationDelay(rs, now)
	if dk == 0 && ds == 0 {
		return true, 0 // both immediately satisfiable; keep (commit) the reservations
	}
	// Denied: refund whatever we reserved so a block on one limiter doesn't burn
	// a token on the other.
	if rk != nil {
		rk.CancelAt(now)
	}
	if rs != nil {
		rs.CancelAt(now)
	}
	if ds > dk {
		return false, ds
	}
	return false, dk
}

// keyActions returns (creating if needed) the per-action limiter map for a key.
func (m *Manager) keyActions(keyID string) map[string]*rate.Limiter {
	actions := m.keyLim[keyID]
	if actions == nil {
		actions = make(map[string]*rate.Limiter)
		m.keyLim[keyID] = actions
	}
	return actions
}

// limiter fetches or creates the limiter for action in the given map, updating
// its rate/burst in place if the resolved limit changed.
func (m *Manager) limiter(into map[string]*rate.Limiter, action string, l Limit) *rate.Limiter {
	want, burst := l.rateLimit(), l.burst()
	lim := into[action]
	if lim == nil {
		lim = rate.NewLimiter(want, burst)
		into[action] = lim
		return lim
	}
	if lim.Limit() != want {
		lim.SetLimit(want)
	}
	if lim.Burst() != burst {
		lim.SetBurst(burst)
	}
	return lim
}

// reservationDelay returns how long until the reserved action is allowed: 0 if
// immediately (or no reservation). A reservation that can never be satisfied
// reports a large delay so the caller treats it as blocked.
func reservationDelay(r *rate.Reservation, now time.Time) time.Duration {
	if r == nil {
		return 0
	}
	if !r.OK() {
		return time.Hour
	}
	return r.DelayFrom(now)
}

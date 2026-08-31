package token

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"harrisonhjones.com/turnstile/internal/store"
)

// touchInterval debounces last-used writes: at most one write per subject per
// interval.
const touchInterval = time.Minute

// Authenticator validates presented tokens and admin credentials against the
// store.
type Authenticator struct {
	store *store.Store
	now   func() time.Time

	// lastTouch tracks the last last-used write time per key, process-globally, so
	// the debounce holds across concurrent requests rather than degenerating into
	// a write per request for a hot key. Subjects are namespaced ("k:") for
	// forward compatibility with other subject kinds.
	touchMu   sync.Mutex
	lastTouch map[string]time.Time

	// touchWG tracks in-flight background last-used writes so shutdown can drain
	// them before the DB is closed (see Wait).
	touchWG sync.WaitGroup
}

func NewAuthenticator(s *store.Store) *Authenticator {
	return &Authenticator{store: s, now: time.Now, lastTouch: make(map[string]time.Time)}
}

// Wait blocks until all in-flight background last-used writes finish. Call it
// during graceful shutdown, after request handlers have quiesced (so no new
// writes are launched) and before closing the store, so a touch write can't
// race a closing DB. Safe to call when none are in flight.
func (a *Authenticator) Wait() { a.touchWG.Wait() }

// shouldTouch reports whether subject's last-used timestamp should be written
// now, recording the decision so concurrent callers debounce against each other.
func (a *Authenticator) shouldTouch(subject string, now time.Time) bool {
	a.touchMu.Lock()
	defer a.touchMu.Unlock()
	if last, ok := a.lastTouch[subject]; ok && now.Sub(last) < touchInterval {
		return false
	}
	a.lastTouch[subject] = now
	return true
}

// Authentication failure reasons. Callers collapse the token failures into a
// single generic response so a caller can't distinguish "no such token" from a
// real-but-disabled/expired one (no enumeration signal).
var (
	ErrMissingToken = errors.New("missing token")
	ErrInvalidToken = errors.New("invalid token")
	ErrKeyDisabled  = errors.New("key disabled")
	ErrKeyExpired   = errors.New("key expired")
)

// Authenticate validates a client API token and returns the resulting
// Principal. It updates the key's last-used timestamp (debounced) on success.
// On failure it returns one of the token Err* sentinels (wrapped for lookup
// errors).
func (a *Authenticator) Authenticate(ctx context.Context, tok string) (*Principal, error) {
	if tok == "" {
		return nil, ErrMissingToken
	}
	key, err := a.store.GetAPIKeyByHash(ctx, Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if key.Disabled {
		return nil, ErrKeyDisabled
	}
	if key.Expired(a.now()) {
		return nil, ErrKeyExpired
	}
	a.touchLastUsed(key)
	return &Principal{Key: key}, nil
}

// touchLastUsed updates the key's last-used timestamp in the background,
// debounced process-globally so a hot key doesn't launch a write goroutine on
// every concurrent request.
func (a *Authenticator) touchLastUsed(key *store.APIKey) {
	now := a.now()
	if !a.shouldTouch("k:"+key.ID, now) {
		return
	}
	a.touchWG.Add(1)
	go func() {
		defer a.touchWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.store.TouchLastUsed(ctx, key.ID, now); err != nil {
			slog.Debug("failed to update last_used_at", "key_id", key.ID, "error", err)
		}
	}()
}

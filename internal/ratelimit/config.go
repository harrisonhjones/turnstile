// Package ratelimit enforces per-action request rate limits at two independent
// levels that must both be satisfied:
//
//   - per key: each API key gets its own limiter per action, resolved from the
//     key's own overrides, then the global per-key defaults.
//   - service-wide: one shared limiter per action caps aggregate throughput
//     across all keys.
//
// Limits are expressed in requests/minute with an optional burst. When burst is
// unset it defaults to ~10 seconds' worth of the rate (rounded up, min 1), so a
// low-rate action is effectively paced while a high-rate one still tolerates
// short clumps. A rate of <= 0 means "no limit".
package ratelimit

import (
	"fmt"
	"math"

	"golang.org/x/time/rate"
)

// maxPerMinute caps configured rates. It's far above any real use and keeps the
// derived burst (ceil(perMinute/6)) well within int range.
const maxPerMinute = 1_000_000

// Limit is a single rate limit: PerMinute requests per minute, with an optional
// Burst (bucket size). PerMinute <= 0 means unlimited. Burst <= 0 means "use the
// default" (see burst()).
type Limit struct {
	PerMinute float64 `json:"perMinute"`
	Burst     int     `json:"burst,omitempty"`
}

// unlimited reports whether this limit imposes no constraint. Validation rejects
// negative rates, so in practice the only value that reaches here as unlimited
// is PerMinute == 0; the <= keeps it robust to any unvalidated construction.
func (l Limit) unlimited() bool { return l.PerMinute <= 0 }

// rateLimit converts PerMinute to tokens/second for x/time/rate.
func (l Limit) rateLimit() rate.Limit {
	if l.unlimited() {
		return rate.Inf
	}
	return rate.Limit(l.PerMinute / 60.0)
}

// burst returns the effective bucket size: the configured Burst if positive,
// else ~10 seconds' worth of the rate (ceil(perMinute/6)), floored at 1.
func (l Limit) burst() int {
	if l.Burst > 0 {
		return l.Burst
	}
	return max(1, int(math.Ceil(l.PerMinute/6.0)))
}

// Config is a set of limits: an optional Default plus per-action overrides. It
// is used for a key's own limits, the global per-key defaults, and the
// service-wide limits.
type Config struct {
	Default   *Limit           `json:"default,omitempty"`
	PerAction map[string]Limit `json:"perAction,omitempty"`
}

// resolve returns the limit this Config specifies for an action: the per-action
// entry if present, else the Default. ok is false if neither is set.
func (c Config) resolve(action string) (Limit, bool) {
	if l, ok := c.PerAction[action]; ok {
		return l, true
	}
	if c.Default != nil {
		return *c.Default, true
	}
	return Limit{}, false
}

// Global holds the rate-limit configuration stored on the global policy: the
// defaults every key inherits (PerKey) and the aggregate caps (ServiceWide).
type Global struct {
	PerKey      Config `json:"perKey,omitempty"`
	ServiceWide Config `json:"serviceWide,omitempty"`
}

// PerActionLimits is a key's own rate-limit overrides: a limit per action. A key
// can only tighten (or loosen) specific actions; it has no blanket default —
// that baseline comes from the global per-key config — so this is a plain
// action→Limit map rather than a Config.
type PerActionLimits map[string]Limit

// Validate rejects malformed limit values in a key's overrides.
func (p PerActionLimits) Validate() error {
	for action, l := range p {
		if err := l.validate("rateLimits." + action); err != nil {
			return err
		}
	}
	return nil
}

// effectiveKey resolves the per-key limit for (keyLimits, action): the key's own
// per-action override first, then the global per-key entry/default.
func effectiveKey(action string, keyLimits PerActionLimits, globalPerKey Config) (Limit, bool) {
	if l, ok := keyLimits[action]; ok {
		return l, true
	}
	return globalPerKey.resolve(action)
}

// Validate rejects malformed limit values in the global configuration.
func (g Global) Validate() error {
	if err := g.PerKey.validate("perKey"); err != nil {
		return err
	}
	return g.ServiceWide.validate("serviceWide")
}

// Validate rejects malformed limit values in a single Config (e.g. a key's own
// overrides).
func (c Config) Validate() error { return c.validate("rateLimits") }

func (c Config) validate(scope string) error {
	if c.Default != nil {
		if err := c.Default.validate(scope + ".default"); err != nil {
			return err
		}
	}
	for action, l := range c.PerAction {
		if err := l.validate(scope + ".perAction." + action); err != nil {
			return err
		}
	}
	return nil
}

func (l Limit) validate(where string) error {
	switch {
	case math.IsNaN(l.PerMinute) || math.IsInf(l.PerMinute, 0):
		return fmt.Errorf("%s: perMinute must be a finite number", where)
	case l.PerMinute < 0:
		return fmt.Errorf("%s: perMinute must not be negative", where)
	case l.PerMinute > maxPerMinute:
		return fmt.Errorf("%s: perMinute must be <= %d", where, maxPerMinute)
	case l.Burst < 0:
		return fmt.Errorf("%s: burst must not be negative", where)
	case l.Burst > maxPerMinute:
		return fmt.Errorf("%s: burst must be <= %d", where, maxPerMinute)
	}
	return nil
}

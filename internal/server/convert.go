package server

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	turnstilev1 "harrisonhjones.com/turnstile/gen/turnstile/v1"
	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/ratelimit"
	"harrisonhjones.com/turnstile/internal/store"
)

// This file translates between the wire (turnstile.v1 protobuf) types and the
// internal domain types. Keeping the mapping in one place lets the handlers and
// the core packages each stay ignorant of the other's representation.

// ---- Effect / Statement ----

func effectFromPB(e turnstilev1.Effect) policy.Effect {
	switch e {
	case turnstilev1.Effect_ALLOW:
		return policy.Allow
	case turnstilev1.Effect_DENY:
		return policy.Deny
	default:
		// EFFECT_UNSPECIFIED maps to the empty effect, which policy validation
		// rejects with a clear message.
		return policy.Effect("")
	}
}

func effectToPB(e policy.Effect) turnstilev1.Effect {
	switch e {
	case policy.Allow:
		return turnstilev1.Effect_ALLOW
	case policy.Deny:
		return turnstilev1.Effect_DENY
	default:
		return turnstilev1.Effect_EFFECT_UNSPECIFIED
	}
}

func statementsFromPB(in []*turnstilev1.Statement) []policy.Statement {
	if in == nil {
		return nil
	}
	out := make([]policy.Statement, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		out = append(out, policy.Statement{
			Effect:    effectFromPB(s.Effect),
			Actions:   s.Actions,
			Resources: s.Resources,
			Note:      s.Note,
		})
	}
	return out
}

func statementsToPB(in []policy.Statement) []*turnstilev1.Statement {
	out := make([]*turnstilev1.Statement, 0, len(in))
	for i := range in {
		s := in[i]
		out = append(out, &turnstilev1.Statement{
			Effect:    effectToPB(s.Effect),
			Actions:   s.Actions,
			Resources: s.Resources,
			Note:      s.Note,
		})
	}
	return out
}

// ---- Rate limits ----

func limitFromPB(l *turnstilev1.Limit) *ratelimit.Limit {
	if l == nil {
		return nil
	}
	return &ratelimit.Limit{PerMinute: l.PerMinute, Burst: int(l.Burst)}
}

func limitToPB(l *ratelimit.Limit) *turnstilev1.Limit {
	if l == nil {
		return nil
	}
	return &turnstilev1.Limit{PerMinute: l.PerMinute, Burst: int32(l.Burst)}
}

func configFromPB(c *turnstilev1.RateLimitConfig) ratelimit.Config {
	if c == nil {
		return ratelimit.Config{}
	}
	out := ratelimit.Config{Default: limitFromPB(c.Default)}
	if len(c.PerAction) > 0 {
		out.PerAction = make(map[string]ratelimit.Limit, len(c.PerAction))
		for action, l := range c.PerAction {
			if l != nil {
				out.PerAction[action] = *limitFromPB(l)
			}
		}
	}
	return out
}

func configToPB(c ratelimit.Config) *turnstilev1.RateLimitConfig {
	out := &turnstilev1.RateLimitConfig{Default: limitToPB(c.Default)}
	if len(c.PerAction) > 0 {
		out.PerAction = make(map[string]*turnstilev1.Limit, len(c.PerAction))
		for action, l := range c.PerAction {
			ll := l
			out.PerAction[action] = limitToPB(&ll)
		}
	}
	return out
}

// perActionFromPB converts a key's wire rate-limit map (action → Limit) to the
// internal PerActionLimits.
func perActionFromPB(in map[string]*turnstilev1.Limit) ratelimit.PerActionLimits {
	if len(in) == 0 {
		return nil
	}
	out := make(ratelimit.PerActionLimits, len(in))
	for action, l := range in {
		if l != nil {
			out[action] = *limitFromPB(l)
		}
	}
	return out
}

func perActionToPB(in ratelimit.PerActionLimits) map[string]*turnstilev1.Limit {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*turnstilev1.Limit, len(in))
	for action, l := range in {
		ll := l
		out[action] = limitToPB(&ll)
	}
	return out
}

func globalFromPB(g *turnstilev1.RateLimits) ratelimit.Global {
	if g == nil {
		return ratelimit.Global{}
	}
	return ratelimit.Global{
		PerKey:      configFromPB(g.PerKey),
		ServiceWide: configFromPB(g.ServiceWide),
	}
}

func globalToPB(g ratelimit.Global) *turnstilev1.RateLimits {
	return &turnstilev1.RateLimits{
		PerKey:      configToPB(g.PerKey),
		ServiceWide: configToPB(g.ServiceWide),
	}
}

// ---- Timestamps ----

func timePtrFromPB(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func timeToPB(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}

func timePtrToPB(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// ---- Keys ----

// keyToPB converts a stored key to its wire form. It never sets plaintext_token
// (that is populated only by the CreateKey handler, which has the plaintext).
func keyToPB(k *store.APIKey) *turnstilev1.Key {
	return &turnstilev1.Key{
		Id:         k.ID,
		Name:       k.Name,
		Note:       k.Note,
		Statements: statementsToPB(k.Statements),
		RateLimits: perActionToPB(k.RateLimits),
		Disabled:   k.Disabled,
		CreatedAt:  timeToPB(k.CreatedAt),
		LastUsedAt: timePtrToPB(k.LastUsedAt),
		ExpiresAt:  timePtrToPB(k.ExpiresAt),
	}
}

func principalToPB(k *store.APIKey) *turnstilev1.Principal {
	return &turnstilev1.Principal{KeyId: k.ID, Name: k.Name, Note: k.Note}
}

// ---- Audit ----

func auditToPB(e *store.AuditEntry) *turnstilev1.AuditEntry {
	// Map the stored decision name to the enum; an unknown/empty string decodes to
	// DECISION_UNSPECIFIED (an honest "unknown") rather than silently to ALLOWED.
	decision := turnstilev1.Decision_DECISION_UNSPECIFIED
	if v, ok := turnstilev1.Decision_value[e.Decision]; ok {
		decision = turnstilev1.Decision(v)
	}
	return &turnstilev1.AuditEntry{
		ApiKeyId:  e.APIKeyID,
		Action:    e.Action,
		Resource:  e.Resource,
		Decision:  decision,
		Timestamp: timeToPB(e.Timestamp),
	}
}

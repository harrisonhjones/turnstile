package token

import (
	"context"

	"github.com/harrisonhjones/turnstile/internal/store"
)

// Principal is the authenticated caller for a Check/Authenticate request: the
// API key that presented a valid token.
type Principal struct {
	Key *store.APIKey
}

type contextKey struct{}

var principalKey contextKey

// WithPrincipal returns a copy of ctx carrying the principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFromContext returns the authenticated principal, or nil if the
// request was not authenticated.
func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey).(*Principal)
	return p
}

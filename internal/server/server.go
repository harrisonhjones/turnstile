// Package server implements the turnstile.v1 Connect service: the Check hot
// path, identity lookup, and the management RPCs (guarded by the caller key's own
// turnstile: grants). It wires together the token, policy, ratelimit, audit, and
// store packages.
//
// # Guarding the guard
//
// There is one credential type — an API key — and one authorization model:
//
//   - Management RPCs (CreateKey, ListKeys, …, RotateKey, UpdatePolicy,
//     QueryAudit) require the caller's key to allow the matching turnstile:<op>
//     action on the target resource (see requireManage). Management is evaluated
//     against the caller key's own statements only — the global deny-only ceiling
//     does not gate it.
//   - The host-facing RPCs (Check, Authenticate) are open at the application
//     layer; deployments guard them with mTLS or network isolation.
//
// Authorization of the end user's request (the Check hot path) keys off the
// namespaced action and the presented client token, never the calling host's
// identity.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	turnstilev1 "harrisonhjones.com/turnstile/gen/turnstile/v1"
	"harrisonhjones.com/turnstile/gen/turnstile/v1/turnstilev1connect"
	"harrisonhjones.com/turnstile/internal/audit"
	"harrisonhjones.com/turnstile/internal/metrics"
	"harrisonhjones.com/turnstile/internal/ratelimit"
	"harrisonhjones.com/turnstile/internal/store"
	"harrisonhjones.com/turnstile/internal/token"
)

// defaultAuditPageSize and maxAuditPageSize bound QueryAudit page sizes.
const (
	defaultAuditPageSize = 100
	maxAuditPageSize     = 1000
)

// Deps are the collaborators a Handler needs.
type Deps struct {
	Store         *store.Store
	Authenticator *token.Authenticator
	Authorizer    *token.Authorizer
	PolicyCache   *token.PolicyCache
	RateLimiter   *ratelimit.Manager
	AuditWriter   *audit.Writer
}

// Handler implements turnstilev1connect.TurnstileHandler.
type Handler struct {
	store       *store.Store
	auth        *token.Authenticator
	authorizer  *token.Authorizer
	policyCache *token.PolicyCache
	rateLimiter *ratelimit.Manager
	auditWriter *audit.Writer
	now         func() time.Time
}

// New builds a Handler from its dependencies.
func New(d Deps) *Handler {
	return &Handler{
		store:       d.Store,
		auth:        d.Authenticator,
		authorizer:  d.Authorizer,
		policyCache: d.PolicyCache,
		rateLimiter: d.RateLimiter,
		auditWriter: d.AuditWriter,
		now:         time.Now,
	}
}

// NewConnectHandler returns the HTTP route prefix and handler for the service.
func (h *Handler) NewConnectHandler(opts ...connect.HandlerOption) (string, http.Handler) {
	return turnstilev1connect.NewTurnstileHandler(h, opts...)
}

// Compile-time check that Handler satisfies the generated interface.
var _ turnstilev1connect.TurnstileHandler = (*Handler)(nil)

// ---- auth helpers ----

// requireManage authenticates the caller's API key and authorizes a management
// action (turnstile:<op>) against the target resource, evaluating the key's own
// statements only — the global deny-only ceiling does NOT gate management (see
// Authorizer.AuthorizeManagement), so a broad global deny can't lock operators
// out. It returns the caller key on success.
//
// A missing/invalid/disabled/expired key collapses to a generic Unauthenticated
// (no enumeration signal); a well-authenticated key that simply lacks the grant
// is PermissionDenied.
func (h *Handler) requireManage(ctx context.Context, hdr http.Header, action string, resources ...string) (*store.APIKey, error) {
	principal, err := h.auth.Authenticate(ctx, token.ExtractBearer(hdr.Get("Authorization")))
	if err != nil {
		if isAuthnFailure(err) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("a valid management key is required"))
		}
		slog.Error("management auth lookup failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not validate credential"))
	}
	if !h.authorizer.AuthorizeManagement(principal.Key, action, resources...).Allowed {
		res := ""
		if len(resources) > 0 {
			res = resources[0]
		}
		// Self-audit the denied attempt: an authenticated key that lacked the grant
		// is a security-relevant signal.
		h.writeManageAudit(principal.Key, action, res, turnstilev1.Decision_POLICY_DENIED)
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("key is not permitted to %s", action))
	}
	return principal.Key, nil
}

// writeManageAudit records a management-plane audit entry (best-effort; a full
// queue during shutdown just drops it). Turnstile self-audits its own management
// RPCs — successful mutations and denied (PermissionDenied) attempts — because it
// is the authority for turnstile:* actions. The Check hot path records its own
// audit row per decision (see recordCheckAudit).
func (h *Handler) writeManageAudit(caller *store.APIKey, action, resource string, d turnstilev1.Decision) {
	var id string
	if caller != nil {
		id = caller.ID
	}
	h.auditWriter.Write(&store.AuditEntry{
		APIKeyID:  id,
		Action:    action,
		Resource:  resource,
		Decision:  d.String(),
		Timestamp: h.now(),
	})
}

// ---- hot path ----

// Check does authn + authz + rate limiting in one round-trip. It never writes
// audit. Rate-limit budget is consumed only when authn and authz both pass and
// count_rate_limit is set, so a denied authz never burns budget.
func (h *Handler) Check(ctx context.Context, req *connect.Request[turnstilev1.CheckRequest]) (*connect.Response[turnstilev1.CheckResponse], error) {
	r := req.Msg

	principal, err := h.auth.Authenticate(ctx, r.ClientToken)
	if err != nil {
		if isAuthnFailure(err) {
			// Generic unauthenticated result — never distinguish unknown vs
			// disabled vs expired (no token-existence leak).
			slog.Debug("check: rejected token", "reason", err)
			metrics.RecordCheck("unauthenticated")
			h.recordCheckAudit("", r.Action, r.Resource, turnstilev1.Decision_UNAUTHENTICATED)
			return connect.NewResponse(&turnstilev1.CheckResponse{
				Allowed:  false,
				Decision: turnstilev1.Decision_UNAUTHENTICATED,
			}), nil
		}
		slog.Error("check: auth lookup failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("authentication failed"))
	}

	pbPrincipal := principalToPB(principal.Key)

	decision := h.authorizer.Authorize(principal.Key, r.Action, r.Resource)
	if !decision.Allowed {
		metrics.RecordCheck("policy_denied")
		h.recordCheckAudit(principal.Key.ID, r.Action, r.Resource, turnstilev1.Decision_POLICY_DENIED)
		return connect.NewResponse(&turnstilev1.CheckResponse{
			Allowed:   false,
			Principal: pbPrincipal,
			Decision:  turnstilev1.Decision_POLICY_DENIED,
		}), nil
	}

	// Authz passed. Consume rate budget only if asked (reserve-then-confirm).
	if r.CountRateLimit {
		ok, retryAfter := h.rateLimiter.Allow(principal.Key.ID, principal.Key.RateLimits, r.Action)
		if !ok {
			metrics.RecordCheck("rate_limited")
			h.recordCheckAudit(principal.Key.ID, r.Action, r.Resource, turnstilev1.Decision_RATE_LIMITED)
			return connect.NewResponse(&turnstilev1.CheckResponse{
				Allowed:   false,
				Principal: pbPrincipal,
				Decision:  turnstilev1.Decision_RATE_LIMITED,
				RateLimit: &turnstilev1.RateLimitVerdict{
					Limited:      true,
					RetryAfterMs: retryAfter.Milliseconds(),
				},
			}), nil
		}
	}

	metrics.RecordCheck("allowed")
	h.recordCheckAudit(principal.Key.ID, r.Action, r.Resource, turnstilev1.Decision_ALLOWED)
	return connect.NewResponse(&turnstilev1.CheckResponse{
		Allowed:   true,
		Principal: pbPrincipal,
		Decision:  turnstilev1.Decision_ALLOWED,
		RateLimit: &turnstilev1.RateLimitVerdict{Limited: false},
	}), nil
}

// recordCheckAudit writes one audit row for a Check decision (best-effort;
// drop-on-full, never blocks the hot path). keyID is empty for an
// unauthenticated Check.
func (h *Handler) recordCheckAudit(keyID, action, resource string, d turnstilev1.Decision) {
	h.auditWriter.Write(&store.AuditEntry{
		APIKeyID:  keyID,
		Action:    action,
		Resource:  resource,
		Decision:  d.String(),
		Timestamp: h.now(),
	})
}

// Authenticate resolves a client token to its Principal (identity only).
func (h *Handler) Authenticate(ctx context.Context, req *connect.Request[turnstilev1.AuthenticateRequest]) (*connect.Response[turnstilev1.Principal], error) {
	principal, err := h.auth.Authenticate(ctx, req.Msg.ClientToken)
	if err != nil {
		if isAuthnFailure(err) {
			slog.Debug("authenticate: rejected token", "reason", err)
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the provided token is not valid"))
		}
		slog.Error("authenticate: lookup failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("authentication failed"))
	}
	return connect.NewResponse(principalToPB(principal.Key)), nil
}

// isAuthnFailure reports whether err is one of the client-facing token
// rejection reasons (as opposed to an internal lookup error).
func isAuthnFailure(err error) bool {
	return errors.Is(err, token.ErrMissingToken) ||
		errors.Is(err, token.ErrInvalidToken) ||
		errors.Is(err, token.ErrKeyDisabled) ||
		errors.Is(err, token.ErrKeyExpired)
}

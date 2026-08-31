// Package server implements the turnstile.v1 Connect service: the Check hot
// path, identity lookup, audit intake, and the admin-guarded management RPCs.
// It wires together the token, policy, ratelimit, audit, and store packages.
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
//   - The host-facing RPCs (Check, Authenticate, ReportAudit) are open at the
//     application layer; deployments guard them with mTLS or network isolation.
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

// maxReportAuditEntries bounds how many entries a single ReportAudit call may
// carry, so one call can't submit an unbounded batch. A host with more buffered
// should split them across calls. It is a var (not a const) only so tests can
// lower it.
var maxReportAuditEntries = 10000

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
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("key is not permitted to %s", action))
	}
	return principal.Key, nil
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
			return connect.NewResponse(&turnstilev1.CheckResponse{
				Allowed:  false,
				Decision: turnstilev1.Decision_UNAUTHENTICATED,
			}), nil
		}
		slog.Error("check: auth lookup failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("authentication failed"))
	}

	pbPrincipal := principalToPB(principal.Key)

	decision := h.authorizer.Authorize(principal.Key, r.Action, r.Resources...)
	if !decision.Allowed {
		metrics.RecordCheck("policy_denied")
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
	return connect.NewResponse(&turnstilev1.CheckResponse{
		Allowed:   true,
		Principal: pbPrincipal,
		Decision:  turnstilev1.Decision_ALLOWED,
		RateLimit: &turnstilev1.RateLimitVerdict{Limited: false},
	}), nil
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

// ReportAudit ingests a batch of audit entries and persists them in the
// background. It returns the count accepted. Unary (not client-streaming) so
// hosts can call it as plain JSON: one POST with a JSON array of entries.
func (h *Handler) ReportAudit(ctx context.Context, req *connect.Request[turnstilev1.ReportAuditRequest]) (*connect.Response[turnstilev1.ReportAuditSummary], error) {
	entries := req.Msg.Entries
	if len(entries) > maxReportAuditEntries {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			fmt.Errorf("ReportAudit accepts at most %d entries per call; split into multiple calls", maxReportAuditEntries))
	}
	var accepted int64
	for _, pb := range entries {
		// Unwind promptly if the handler context is cancelled (e.g. the
		// ShutdownGate cancels it on shutdown) instead of working through the rest
		// of the batch; return the partial count already persisted so the caller
		// can retry the remainder. (Write itself drains on shutdown, so it won't
		// stay blocked across this check.)
		if ctx.Err() != nil {
			break
		}
		entry := auditFromPB(pb)
		if entry.Timestamp.IsZero() {
			entry.Timestamp = h.now()
		}
		// Count only entries the writer actually accepted, so the returned total
		// never over-reports (e.g. an entry dropped because shutdown began).
		if h.auditWriter.Write(entry) {
			accepted++
		}
	}
	return connect.NewResponse(&turnstilev1.ReportAuditSummary{Accepted: accepted}), nil
}

// isAuthnFailure reports whether err is one of the client-facing token
// rejection reasons (as opposed to an internal lookup error).
func isAuthnFailure(err error) bool {
	return errors.Is(err, token.ErrMissingToken) ||
		errors.Is(err, token.ErrInvalidToken) ||
		errors.Is(err, token.ErrKeyDisabled) ||
		errors.Is(err, token.ErrKeyExpired)
}

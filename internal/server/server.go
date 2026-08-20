// Package server implements the turnstile.v1 Connect service: the Check hot
// path, identity lookup, audit intake, and the admin-guarded management RPCs.
// It wires together the token, policy, ratelimit, audit, and store packages.
//
// # Guarding the guard
//
// Two credentials gate access, enforced per-RPC rather than by a blanket
// interceptor so each method's requirement reads locally:
//
//   - Management RPCs (CreateKey, ListKeys, …, UpdatePolicy, QueryAudit) require
//     an admin credential in the Authorization: Bearer metadata.
//   - The host-facing RPCs (Check, Authenticate, ReportAudit) optionally require
//     a shared service credential (SERVICE_CREDENTIAL); when it is unset they
//     are open, on the assumption that mTLS or network isolation guards them.
//
// Authorization of the end user's request keys off the namespaced action and
// the presented client token, never the calling host's identity.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	turnstilev1 "github.com/harrisonhjones/turnstile/gen/turnstile/v1"
	"github.com/harrisonhjones/turnstile/gen/turnstile/v1/turnstilev1connect"
	"github.com/harrisonhjones/turnstile/internal/audit"
	"github.com/harrisonhjones/turnstile/internal/ratelimit"
	"github.com/harrisonhjones/turnstile/internal/store"
	"github.com/harrisonhjones/turnstile/internal/token"
)

// defaultAuditPageSize and maxAuditPageSize bound QueryAudit page sizes.
const (
	defaultAuditPageSize = 100
	maxAuditPageSize     = 1000
)

// maxReportAuditEntries bounds how many entries a single ReportAudit call may
// stream, so one client can't hold an unbounded intake open. A host that has
// more buffered should split them across calls.
const maxReportAuditEntries = 10000

// Deps are the collaborators a Handler needs.
type Deps struct {
	Store             *store.Store
	Authenticator     *token.Authenticator
	Authorizer        *token.Authorizer
	PolicyCache       *token.PolicyCache
	RateLimiter       *ratelimit.Manager
	AuditWriter       *audit.Writer
	ServiceCredential string // required on Check/Authenticate/ReportAudit if non-empty
}

// Handler implements turnstilev1connect.TurnstileHandler.
type Handler struct {
	store             *store.Store
	auth              *token.Authenticator
	authorizer        *token.Authorizer
	policyCache       *token.PolicyCache
	rateLimiter       *ratelimit.Manager
	auditWriter       *audit.Writer
	serviceCredential string
	now               func() time.Time
}

// New builds a Handler from its dependencies.
func New(d Deps) *Handler {
	return &Handler{
		store:             d.Store,
		auth:              d.Authenticator,
		authorizer:        d.Authorizer,
		policyCache:       d.PolicyCache,
		rateLimiter:       d.RateLimiter,
		auditWriter:       d.AuditWriter,
		serviceCredential: d.ServiceCredential,
		now:               time.Now,
	}
}

// NewConnectHandler returns the HTTP route prefix and handler for the service.
func (h *Handler) NewConnectHandler(opts ...connect.HandlerOption) (string, http.Handler) {
	return turnstilev1connect.NewTurnstileHandler(h, opts...)
}

// Compile-time check that Handler satisfies the generated interface.
var _ turnstilev1connect.TurnstileHandler = (*Handler)(nil)

// ---- auth helpers ----

// requireService enforces the shared service credential on host-facing RPCs. It
// is a no-op when no service credential is configured (mTLS/network isolation
// is assumed to guard the endpoint instead).
func (h *Handler) requireService(hdr http.Header) error {
	if h.serviceCredential == "" {
		return nil
	}
	presented := token.ExtractBearer(hdr.Get("Authorization"))
	if subtle.ConstantTimeCompare([]byte(presented), []byte(h.serviceCredential)) != 1 {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("a valid service credential is required"))
	}
	return nil
}

// requireAdmin validates the admin credential in the request metadata and
// returns the matched credential. Missing/invalid both map to Unauthenticated
// with a generic message.
func (h *Handler) requireAdmin(ctx context.Context, hdr http.Header) (*store.AdminCredential, error) {
	cred := token.ExtractBearer(hdr.Get("Authorization"))
	ac, err := h.auth.AuthenticateAdmin(ctx, cred)
	if err != nil {
		if errors.Is(err, token.ErrMissingAdmin) || errors.Is(err, token.ErrInvalidAdmin) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("a valid admin credential is required"))
		}
		slog.Error("admin auth lookup failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not validate admin credential"))
	}
	return ac, nil
}

// ---- hot path ----

// Check does authn + authz + rate limiting in one round-trip. It never writes
// audit. Rate-limit budget is consumed only when authn and authz both pass and
// count_rate_limit is set, so a denied authz never burns budget.
func (h *Handler) Check(ctx context.Context, req *connect.Request[turnstilev1.CheckRequest]) (*connect.Response[turnstilev1.CheckResponse], error) {
	if err := h.requireService(req.Header()); err != nil {
		return nil, err
	}
	r := req.Msg

	principal, err := h.auth.Authenticate(ctx, r.ClientToken)
	if err != nil {
		if isAuthnFailure(err) {
			// Generic unauthenticated result — never distinguish unknown vs
			// disabled vs expired (no token-existence leak).
			slog.Debug("check: rejected token", "reason", err)
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

	return connect.NewResponse(&turnstilev1.CheckResponse{
		Allowed:   true,
		Principal: pbPrincipal,
		Decision:  turnstilev1.Decision_ALLOWED,
		RateLimit: &turnstilev1.RateLimitVerdict{Limited: false},
	}), nil
}

// Authenticate resolves a client token to its Principal (identity only).
func (h *Handler) Authenticate(ctx context.Context, req *connect.Request[turnstilev1.AuthenticateRequest]) (*connect.Response[turnstilev1.Principal], error) {
	if err := h.requireService(req.Header()); err != nil {
		return nil, err
	}
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

// ReportAudit ingests a stream of audit entries and persists them in the
// background. It returns the count accepted.
func (h *Handler) ReportAudit(ctx context.Context, stream *connect.ClientStream[turnstilev1.AuditEntry]) (*connect.Response[turnstilev1.ReportAuditSummary], error) {
	if err := h.requireService(stream.RequestHeader()); err != nil {
		return nil, err
	}
	var accepted int64
	for stream.Receive() {
		if accepted >= maxReportAuditEntries {
			return nil, connect.NewError(connect.CodeResourceExhausted,
				fmt.Errorf("ReportAudit accepts at most %d entries per call; split into multiple calls", maxReportAuditEntries))
		}
		entry := auditFromPB(stream.Msg())
		if entry.Timestamp.IsZero() {
			entry.Timestamp = h.now()
		}
		h.auditWriter.Write(entry)
		accepted++
	}
	if err := stream.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, connect.NewError(connect.CodeInternal, err)
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

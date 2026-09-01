package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	turnstilev1 "harrisonhjones.com/turnstile/gen/turnstile/v1"
	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/store"
	"harrisonhjones.com/turnstile/internal/token"
)

// storeErr maps store sentinel errors to appropriate Connect codes.
func storeErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrNameTaken):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrVersionConflict):
		return connect.NewError(connect.CodeAborted, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func invalidArg(format string, args ...any) error {
	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(format, args...))
}

// CreateKey mints a new API key and returns it with the plaintext token set
// exactly once.
func (h *Handler) CreateKey(ctx context.Context, req *connect.Request[turnstilev1.CreateKeyRequest]) (*connect.Response[turnstilev1.Key], error) {
	caller, err := h.requireManage(ctx, req.Header(), "turnstile:create-key", "*")
	if err != nil {
		return nil, err
	}
	r := req.Msg
	if r.Name == "" {
		return nil, invalidArg("name is required")
	}
	statements := statementsFromPB(r.Statements)
	if err := policy.ValidateStatements(statements); err != nil {
		return nil, invalidArg("statements: %v", err)
	}
	limits := perActionFromPB(r.RateLimits)
	if err := limits.Validate(); err != nil {
		return nil, invalidArg("rate limits: %v", err)
	}

	plaintext, hash, err := token.Generate(token.APIKeyPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	k := &store.APIKey{
		ID:         token.NewID("key"),
		Name:       r.Name,
		KeyHash:    hash,
		Statements: statements,
		RateLimits: limits,
		Note:       r.Note,
		CreatedAt:  h.now(),
		ExpiresAt:  timePtrFromPB(r.ExpiresAt),
		Disabled:   r.Disabled,
	}
	if err := h.store.CreateAPIKey(ctx, k); err != nil {
		return nil, storeErr(err)
	}
	h.writeManageAudit(caller, "turnstile:create-key", k.ID, turnstilev1.Decision_ALLOWED)

	pbKey := keyToPB(k)
	pbKey.PlaintextToken = plaintext
	return connect.NewResponse(pbKey), nil
}

// ListKeys returns keys, optionally including disabled ones.
func (h *Handler) ListKeys(ctx context.Context, req *connect.Request[turnstilev1.ListKeysRequest]) (*connect.Response[turnstilev1.ListKeysResponse], error) {
	if _, err := h.requireManage(ctx, req.Header(), "turnstile:list-keys", "*"); err != nil {
		return nil, err
	}
	keys, err := h.store.ListAPIKeys(ctx, req.Msg.IncludeDisabled)
	if err != nil {
		return nil, storeErr(err)
	}
	out := make([]*turnstilev1.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyToPB(k))
	}
	return connect.NewResponse(&turnstilev1.ListKeysResponse{Keys: out}), nil
}

// GetKey returns a single key by id.
func (h *Handler) GetKey(ctx context.Context, req *connect.Request[turnstilev1.GetKeyRequest]) (*connect.Response[turnstilev1.Key], error) {
	if _, err := h.requireManage(ctx, req.Header(), "turnstile:get-key", req.Msg.Id); err != nil {
		return nil, err
	}
	if req.Msg.Id == "" {
		return nil, invalidArg("id is required")
	}
	k, err := h.store.GetAPIKeyByID(ctx, req.Msg.Id)
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(keyToPB(k)), nil
}

// UpdateKey applies a partial update. Absent scalar fields and absent
// statements/rate_limits are left unchanged; expiry is set via expires_at or
// removed via clear_expiry.
func (h *Handler) UpdateKey(ctx context.Context, req *connect.Request[turnstilev1.UpdateKeyRequest]) (*connect.Response[turnstilev1.Key], error) {
	r := req.Msg
	caller, err := h.requireManage(ctx, req.Header(), "turnstile:update-key", r.Id)
	if err != nil {
		return nil, err
	}
	if r.Id == "" {
		return nil, invalidArg("id is required")
	}
	if r.ClearExpiry && r.ExpiresAt != nil {
		return nil, invalidArg("expires_at and clear_expiry are mutually exclusive")
	}
	if r.ClearRateLimits && len(r.RateLimits) > 0 {
		return nil, invalidArg("rate_limits and clear_rate_limits are mutually exclusive")
	}

	var validationErr error
	updated, err := h.store.UpdateAPIKeyFunc(ctx, r.Id, func(k *store.APIKey) error {
		if r.Name != nil {
			if *r.Name == "" {
				validationErr = invalidArg("name must not be empty")
				return validationErr
			}
			k.Name = *r.Name
		}
		if r.Note != nil {
			k.Note = *r.Note
		}
		if r.Disabled != nil {
			k.Disabled = *r.Disabled
		}
		if r.Statements != nil {
			statements := statementsFromPB(r.Statements.Statements)
			if verr := policy.ValidateStatements(statements); verr != nil {
				validationErr = invalidArg("statements: %v", verr)
				return validationErr
			}
			k.Statements = statements
		}
		// rate_limits: a map has no presence, so a non-empty map replaces the
		// key's overrides, clear_rate_limits removes them all, and an empty/absent
		// map leaves them unchanged.
		if r.ClearRateLimits {
			k.RateLimits = nil
		} else if len(r.RateLimits) > 0 {
			limits := perActionFromPB(r.RateLimits)
			if verr := limits.Validate(); verr != nil {
				validationErr = invalidArg("rate limits: %v", verr)
				return validationErr
			}
			k.RateLimits = limits
		}
		if r.ClearExpiry {
			k.ExpiresAt = nil
		} else if r.ExpiresAt != nil {
			k.ExpiresAt = timePtrFromPB(r.ExpiresAt)
		}
		return nil
	})
	if validationErr != nil {
		return nil, validationErr
	}
	if err != nil {
		return nil, storeErr(err)
	}
	h.writeManageAudit(caller, "turnstile:update-key", r.Id, turnstilev1.Decision_ALLOWED)
	return connect.NewResponse(keyToPB(updated)), nil
}

// RotateKey regenerates a key's secret in place: same id, policy, rate limits,
// and name. The new plaintext token is returned exactly once; the old token
// stops authenticating immediately.
func (h *Handler) RotateKey(ctx context.Context, req *connect.Request[turnstilev1.RotateKeyRequest]) (*connect.Response[turnstilev1.Key], error) {
	caller, err := h.requireManage(ctx, req.Header(), "turnstile:rotate-key", req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if req.Msg.Id == "" {
		return nil, invalidArg("id is required")
	}
	plaintext, hash, err := token.Generate(token.APIKeyPrefix)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	updated, err := h.store.RotateAPIKey(ctx, req.Msg.Id, hash)
	if err != nil {
		return nil, storeErr(err)
	}
	h.writeManageAudit(caller, "turnstile:rotate-key", req.Msg.Id, turnstilev1.Decision_ALLOWED)
	pbKey := keyToPB(updated)
	pbKey.PlaintextToken = plaintext
	return connect.NewResponse(pbKey), nil
}

// DeleteKey removes a key and drops its cached rate limiters.
func (h *Handler) DeleteKey(ctx context.Context, req *connect.Request[turnstilev1.DeleteKeyRequest]) (*connect.Response[emptypb.Empty], error) {
	caller, err := h.requireManage(ctx, req.Header(), "turnstile:delete-key", req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if req.Msg.Id == "" {
		return nil, invalidArg("id is required")
	}
	if err := h.store.DeleteAPIKey(ctx, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	h.rateLimiter.ForgetKey(req.Msg.Id)
	h.writeManageAudit(caller, "turnstile:delete-key", req.Msg.Id, turnstilev1.Decision_ALLOWED)
	return connect.NewResponse(&emptypb.Empty{}), nil
}

// GetPolicy returns the global policy.
func (h *Handler) GetPolicy(ctx context.Context, req *connect.Request[turnstilev1.GetPolicyRequest]) (*connect.Response[turnstilev1.Policy], error) {
	if _, err := h.requireManage(ctx, req.Header(), "turnstile:read-policy", "*"); err != nil {
		return nil, err
	}
	gp, err := h.store.GetGlobalPolicy(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(policyToPB(gp)), nil
}

// UpdatePolicy replaces the global policy with an optimistic version check. The
// global policy is a deny-only ceiling, so allow statements are rejected. On
// success it refreshes the in-memory policy cache and the rate limiter.
func (h *Handler) UpdatePolicy(ctx context.Context, req *connect.Request[turnstilev1.UpdatePolicyRequest]) (*connect.Response[turnstilev1.Policy], error) {
	callerKey, err := h.requireManage(ctx, req.Header(), "turnstile:update-policy", "*")
	if err != nil {
		return nil, err
	}
	r := req.Msg
	statements := statementsFromPB(r.Statements)
	if verr := policy.ValidateGlobalStatements(statements); verr != nil {
		return nil, invalidArg("statements: %v", verr)
	}
	limits := globalFromPB(r.RateLimits)
	if verr := limits.Validate(); verr != nil {
		return nil, invalidArg("rate limits: %v", verr)
	}

	gp := &store.GlobalPolicy{
		Statements:  statements,
		Constraints: store.Constraints{RateLimits: limits},
		UpdatedAt:   h.now(),
		UpdatedBy:   callerKey.Name,
	}
	if err := h.store.UpdateGlobalPolicy(ctx, gp, int(r.ExpectedVersion)); err != nil {
		return nil, storeErr(err)
	}

	// Refresh caches so authorization and rate limiting reflect the new policy
	// without a restart.
	h.policyCache.Set(gp)
	h.rateLimiter.SetGlobal(limits)

	h.writeManageAudit(callerKey, "turnstile:update-policy", "*", turnstilev1.Decision_ALLOWED)
	return connect.NewResponse(policyToPB(gp)), nil
}

// QueryAudit returns audit entries matching the filter, newest first.
func (h *Handler) QueryAudit(ctx context.Context, req *connect.Request[turnstilev1.QueryAuditRequest]) (*connect.Response[turnstilev1.QueryAuditResponse], error) {
	if _, err := h.requireManage(ctx, req.Header(), "turnstile:query-audit", "*"); err != nil {
		return nil, err
	}
	r := req.Msg
	limit := int(r.Limit)
	if limit <= 0 {
		limit = defaultAuditPageSize
	}
	if limit > maxAuditPageSize {
		limit = maxAuditPageSize
	}
	filter := store.AuditFilter{
		APIKeyID:     r.ApiKeyId,
		ActionPrefix: r.ActionPrefix,
		After:        timePtrFromPB(r.After),
		Before:       timePtrFromPB(r.Before),
		Limit:        limit,
		Cursor:       r.Cursor,
	}
	if r.Decision != nil {
		filter.Decision = r.Decision.String()
	}
	entries, nextCursor, err := h.store.ListAuditEntries(ctx, filter)
	if err != nil {
		return nil, storeErr(err)
	}
	out := make([]*turnstilev1.AuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditToPB(e))
	}
	return connect.NewResponse(&turnstilev1.QueryAuditResponse{Entries: out, NextCursor: nextCursor}), nil
}

// policyToPB converts the stored global policy to its wire form.
func policyToPB(gp *store.GlobalPolicy) *turnstilev1.Policy {
	return &turnstilev1.Policy{
		Statements: statementsToPB(gp.Statements),
		RateLimits: globalToPB(gp.Constraints.RateLimits),
		Version:    int64(gp.Version),
		UpdatedAt:  timeToPB(gp.UpdatedAt),
		UpdatedBy:  gp.UpdatedBy,
	}
}

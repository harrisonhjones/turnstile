package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	turnstilev1 "harrisonhjones.com/turnstile/gen/turnstile/v1"
	"harrisonhjones.com/turnstile/gen/turnstile/v1/turnstilev1connect"
	"harrisonhjones.com/turnstile/internal/audit"
	"harrisonhjones.com/turnstile/internal/metrics"
	"harrisonhjones.com/turnstile/internal/ratelimit"
	"harrisonhjones.com/turnstile/internal/store"
	"harrisonhjones.com/turnstile/internal/token"
)

// testEnv is a running in-process Turnstile: a real store, handler, and HTTP
// test server, plus a Connect client and the bootstrap admin token.
type testEnv struct {
	client     turnstilev1connect.TurnstileClient
	adminToken string
	store      *store.Store
}

func withAdmin(env *testEnv, req connect.AnyRequest) {
	req.Header().Set("Authorization", "Bearer "+env.adminToken)
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvOpts(t)
}

// newTestEnvOpts builds an env. Optional wrap functions decorate the Connect
// handler (e.g. the metrics Instrument middleware) so tests can exercise the same
// wrapping main.go applies. The bootstrap token it returns is a full-admin key
// (allow turnstile:* on *), so withAdmin authorizes any management RPC.
func newTestEnvOpts(t *testing.T, wrap ...func(http.Handler) http.Handler) *testEnv {
	t.Helper()
	ctx := context.Background()

	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	adminToken, err := token.BootstrapIfEmpty(ctx, s, time.Now())
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	gp, _ := s.GetGlobalPolicy(ctx)
	cache := token.NewPolicyCache(gp)
	rl := ratelimit.New(gp.Constraints.RateLimits)

	writer := audit.NewWriter(s)
	// Drain the writer before the store is closed (cleanups run LIFO, and the
	// store-close cleanup was registered first, so it runs after this).
	t.Cleanup(writer.Wait)

	h := New(Deps{
		Store:         s,
		Authenticator: token.NewAuthenticator(s),
		Authorizer:    token.NewAuthorizer(cache),
		PolicyCache:   cache,
		RateLimiter:   rl,
		AuditWriter:   writer,
	})

	path, handler := h.NewConnectHandler()
	for _, w := range wrap {
		handler = w(handler)
	}
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := turnstilev1connect.NewTurnstileClient(ts.Client(), ts.URL)
	return &testEnv{client: client, adminToken: adminToken, store: s}
}

func TestServiceEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// --- CreateKey requires admin ---
	noAuth := connect.NewRequest(&turnstilev1.CreateKeyRequest{Name: "x", Statements: allowAll()})
	if _, err := env.client.CreateKey(ctx, noAuth); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("CreateKey without admin: got %v, want Unauthenticated", connect.CodeOf(err))
	}

	// --- CreateKey returns a plaintext token once ---
	createReq := connect.NewRequest(&turnstilev1.CreateKeyRequest{
		Name:       "reader",
		Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:read"}, Resources: []string{"svc:*"}}},
	})
	withAdmin(env, createReq)
	created, err := env.client.CreateKey(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	clientToken := created.Msg.PlaintextToken
	if clientToken == "" {
		t.Fatal("CreateKey should return a plaintext token")
	}

	// --- Check: allowed action ---
	allowResp, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: clientToken, Action: "svc:read", Resources: []string{"svc:thing:1"}, CountRateLimit: true,
	}))
	if err != nil {
		t.Fatalf("Check allowed: %v", err)
	}
	if !allowResp.Msg.Allowed || allowResp.Msg.Decision != turnstilev1.Decision_ALLOWED {
		t.Errorf("expected ALLOWED, got %+v", allowResp.Msg)
	}
	if allowResp.Msg.Principal.GetName() != "reader" {
		t.Errorf("expected principal name reader, got %q", allowResp.Msg.Principal.GetName())
	}

	// --- Check: denied action (not granted) ---
	denyResp, _ := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: clientToken, Action: "svc:write", Resources: []string{"svc:thing:1"},
	}))
	if denyResp.Msg.Allowed || denyResp.Msg.Decision != turnstilev1.Decision_POLICY_DENIED {
		t.Errorf("expected POLICY_DENIED, got %+v", denyResp.Msg)
	}

	// --- Check: bad token is generically UNAUTHENTICATED ---
	unauthResp, _ := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: "tsk_bogus", Action: "svc:read", Resources: []string{"svc:thing:1"},
	}))
	if unauthResp.Msg.Allowed || unauthResp.Msg.Decision != turnstilev1.Decision_UNAUTHENTICATED {
		t.Errorf("expected UNAUTHENTICATED, got %+v", unauthResp.Msg)
	}

	// --- Authenticate (whoami) ---
	who, err := env.client.Authenticate(ctx, connect.NewRequest(&turnstilev1.AuthenticateRequest{ClientToken: clientToken}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if who.Msg.KeyId != created.Msg.Id {
		t.Errorf("Authenticate key id mismatch: %q vs %q", who.Msg.KeyId, created.Msg.Id)
	}

	// --- ReportAudit (unary batch) ---
	entries := make([]*turnstilev1.AuditEntry, 0, 3)
	for i := 0; i < 3; i++ {
		entries = append(entries, &turnstilev1.AuditEntry{
			ApiKeyId: created.Msg.Id, ApiKeyName: "reader", Method: "REST", Path: "/x",
			Action: "svc:read", ResponseStatus: 200, LatencyMs: 3,
		})
	}
	summary, err := env.client.ReportAudit(ctx, connect.NewRequest(&turnstilev1.ReportAuditRequest{Entries: entries}))
	if err != nil {
		t.Fatalf("ReportAudit: %v", err)
	}
	if summary.Msg.Accepted != 3 {
		t.Errorf("expected 3 accepted, got %d", summary.Msg.Accepted)
	}

	// Audit writes are async; wait until visible.
	waitForAudit(t, env, 3)

	// --- QueryAudit ---
	qReq := connect.NewRequest(&turnstilev1.QueryAuditRequest{ActionPrefix: "svc:", Limit: 10})
	withAdmin(env, qReq)
	q, err := env.client.QueryAudit(ctx, qReq)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(q.Msg.Entries) != 3 {
		t.Errorf("expected 3 audit entries, got %d", len(q.Msg.Entries))
	}
}

// TestReportAuditCap verifies ReportAudit rejects a batch past the entry cap
// with ResourceExhausted (the whole batch atomically — nothing persisted),
// while a batch exactly at the cap is accepted.
func TestReportAuditCap(t *testing.T) {
	orig := maxReportAuditEntries
	maxReportAuditEntries = 3
	t.Cleanup(func() { maxReportAuditEntries = orig })

	env := newTestEnv(t)
	ctx := context.Background()

	entry := func() *turnstilev1.AuditEntry {
		return &turnstilev1.AuditEntry{
			ApiKeyId: "k", ApiKeyName: "n", Method: "REST", Path: "/x", Action: "svc:read", ResponseStatus: 200,
		}
	}
	batch := func(n int) *connect.Request[turnstilev1.ReportAuditRequest] {
		entries := make([]*turnstilev1.AuditEntry, 0, n)
		for i := 0; i < n; i++ {
			entries = append(entries, entry())
		}
		return connect.NewRequest(&turnstilev1.ReportAuditRequest{Entries: entries})
	}

	// One past the cap: the whole batch is rejected, nothing persisted.
	if _, err := env.client.ReportAudit(ctx, batch(maxReportAuditEntries+1)); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("expected ResourceExhausted past the cap, got %v", connect.CodeOf(err))
	}

	// A batch exactly at the cap is accepted and persisted.
	summary, err := env.client.ReportAudit(ctx, batch(maxReportAuditEntries))
	if err != nil {
		t.Fatalf("ReportAudit at cap: %v", err)
	}
	if summary.Msg.Accepted != int64(maxReportAuditEntries) {
		t.Errorf("expected %d accepted, got %d", maxReportAuditEntries, summary.Msg.Accepted)
	}
	waitForAudit(t, env, maxReportAuditEntries)
}

// TestCheckThroughMetricsInstrument exercises the real Connect handler wrapped by
// the metrics Instrument middleware — the default (metrics-on) hot path that
// main.go wires up. No other test covers it: the metrics package test wraps a
// trivial HandlerFunc, and the other server tests build the handler unwrapped. It
// confirms Check still works through the wrapper and that the request is counted.
func TestCheckThroughMetricsInstrument(t *testing.T) {
	m := metrics.Enable()
	env := newTestEnvOpts(t, m.Instrument)
	ctx := context.Background()

	createReq := connect.NewRequest(&turnstilev1.CreateKeyRequest{
		Name:       "reader",
		Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:read"}, Resources: []string{"svc:*"}}},
	})
	withAdmin(env, createReq)
	created, err := env.client.CreateKey(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	resp, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: created.Msg.PlaintextToken, Action: "svc:read", Resources: []string{"svc:thing:1"},
	}))
	if err != nil {
		t.Fatalf("Check through instrumented handler: %v", err)
	}
	if resp.Msg.Decision != turnstilev1.Decision_ALLOWED {
		t.Fatalf("expected ALLOWED through instrumented handler, got %v", resp.Msg.Decision)
	}

	// The instrumented handler should have counted the request(s).
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), `turnstile_http_requests_total{code="200"}`) {
		t.Errorf("expected turnstile_http_requests_total{code=\"200\"} in scrape, got:\n%s", body)
	}
}

func TestRateLimitDoesNotBurnOnDeny(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// A key with a strict per-action rate limit (1/min, burst 1) on svc:read.
	createReq := connect.NewRequest(&turnstilev1.CreateKeyRequest{
		Name:       "limited",
		Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:read"}, Resources: []string{"svc:*"}}},
		RateLimits: map[string]*turnstilev1.Limit{"svc:read": {PerMinute: 60, Burst: 1}},
	})
	withAdmin(env, createReq)
	created, err := env.client.CreateKey(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	tok := created.Msg.PlaintextToken

	check := func(count bool) *turnstilev1.CheckResponse {
		resp, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
			ClientToken: tok, Action: "svc:read", Resources: []string{"svc:thing:1"}, CountRateLimit: count,
		}))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		return resp.Msg
	}

	// A denied action must never consume budget even with count_rate_limit set:
	// many denied writes, then the single read budget is still intact.
	for i := 0; i < 5; i++ {
		denied, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
			ClientToken: tok, Action: "svc:write", Resources: []string{"svc:thing:1"}, CountRateLimit: true,
		}))
		if err != nil {
			t.Fatalf("Check write: %v", err)
		}
		if denied.Msg.Decision != turnstilev1.Decision_POLICY_DENIED {
			t.Fatalf("write should be POLICY_DENIED, got %v", denied.Msg.Decision)
		}
	}

	// First counted read is allowed; the second is rate-limited.
	if got := check(true); got.Decision != turnstilev1.Decision_ALLOWED {
		t.Fatalf("first read should be ALLOWED, got %v", got.Decision)
	}
	second := check(true)
	if second.Decision != turnstilev1.Decision_RATE_LIMITED || !second.RateLimit.GetLimited() {
		t.Fatalf("second read should be RATE_LIMITED, got %+v", second)
	}
	if second.RateLimit.GetRetryAfterMs() <= 0 {
		t.Errorf("rate-limited response should carry a positive retry_after_ms")
	}
}

func TestUpdatePolicyVersionConflict(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	getReq := connect.NewRequest(&turnstilev1.GetPolicyRequest{})
	withAdmin(env, getReq)
	pol, err := env.client.GetPolicy(ctx, getReq)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	version := pol.Msg.Version

	// A global allow is rejected (deny-only ceiling).
	badReq := connect.NewRequest(&turnstilev1.UpdatePolicyRequest{
		Statements:      []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"*"}, Resources: []string{"*"}}},
		ExpectedVersion: version,
	})
	withAdmin(env, badReq)
	if _, err := env.client.UpdatePolicy(ctx, badReq); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("global allow should be InvalidArgument, got %v", connect.CodeOf(err))
	}

	// A valid deny update with the right version succeeds.
	okReq := connect.NewRequest(&turnstilev1.UpdatePolicyRequest{
		Statements:      []*turnstilev1.Statement{{Effect: turnstilev1.Effect_DENY, Actions: []string{"svc:danger"}, Resources: []string{"*"}}},
		ExpectedVersion: version,
	})
	withAdmin(env, okReq)
	updated, err := env.client.UpdatePolicy(ctx, okReq)
	if err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if updated.Msg.Version != version+1 {
		t.Errorf("expected version %d, got %d", version+1, updated.Msg.Version)
	}

	// Reusing the stale version is aborted.
	staleReq := connect.NewRequest(&turnstilev1.UpdatePolicyRequest{
		Statements:      []*turnstilev1.Statement{{Effect: turnstilev1.Effect_DENY, Actions: []string{"svc:other"}, Resources: []string{"*"}}},
		ExpectedVersion: version,
	})
	withAdmin(env, staleReq)
	if _, err := env.client.UpdatePolicy(ctx, staleReq); connect.CodeOf(err) != connect.CodeAborted {
		t.Errorf("stale version should be Aborted, got %v", connect.CodeOf(err))
	}
}

func allowAll() []*turnstilev1.Statement {
	return []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"*"}, Resources: []string{"*"}}}
}

// mustCreateKey creates a key as admin and returns it (including plaintextToken).
func mustCreateKey(t *testing.T, env *testEnv, req *turnstilev1.CreateKeyRequest) *turnstilev1.Key {
	t.Helper()
	r := connect.NewRequest(req)
	withAdmin(env, r)
	resp, err := env.client.CreateKey(context.Background(), r)
	if err != nil {
		t.Fatalf("CreateKey(%s): %v", req.Name, err)
	}
	return resp.Msg
}

// withToken sets an explicit bearer token, for exercising management
// authorization with keys other than the bootstrap admin.
func withToken(req connect.AnyRequest, tok string) {
	req.Header().Set("Authorization", "Bearer "+tok)
}

// TestManagementRequiresGrant: management needs a key that allows the turnstile:
// action. No credential is Unauthenticated; an authenticated-but-ungranted key is
// PermissionDenied.
func TestManagementRequiresGrant(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// A key with only business grants — no turnstile: action.
	plain := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "plain", Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:*"}, Resources: []string{"*"}}},
	})

	if _, err := env.client.ListKeys(ctx, connect.NewRequest(&turnstilev1.ListKeysRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("ListKeys with no credential: got %v, want Unauthenticated", connect.CodeOf(err))
	}
	r := connect.NewRequest(&turnstilev1.ListKeysRequest{})
	withToken(r, plain.PlaintextToken)
	if _, err := env.client.ListKeys(ctx, r); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("ListKeys with an ungranted key: got %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestManagementScopedGrant: turnstile:update-key scoped to one key id allows
// updating that key but not another.
func TestManagementScopedGrant(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	target := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{Name: "target", Statements: allowAll()})
	other := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{Name: "other", Statements: allowAll()})
	mgr := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name:       "mgr",
		Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"turnstile:update-key"}, Resources: []string{target.Id}}},
	})

	upd := func(id string) error {
		note := "scoped-touch"
		r := connect.NewRequest(&turnstilev1.UpdateKeyRequest{Id: id, Note: &note})
		withToken(r, mgr.PlaintextToken)
		_, err := env.client.UpdateKey(ctx, r)
		return err
	}
	if err := upd(target.Id); err != nil {
		t.Errorf("scoped manager should update its target: %v", err)
	}
	if err := upd(other.Id); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("scoped manager updating another key: got %v, want PermissionDenied", connect.CodeOf(err))
	}
}

// TestManagementIgnoresGlobalCeiling: a global deny of turnstile:* must not lock
// out a full-admin key — management is evaluated against the key alone.
func TestManagementIgnoresGlobalCeiling(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	getReq := connect.NewRequest(&turnstilev1.GetPolicyRequest{})
	withAdmin(env, getReq)
	pol, err := env.client.GetPolicy(ctx, getReq)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	upReq := connect.NewRequest(&turnstilev1.UpdatePolicyRequest{
		Statements:      []*turnstilev1.Statement{{Effect: turnstilev1.Effect_DENY, Actions: []string{"turnstile:*"}, Resources: []string{"*"}}},
		RateLimits:      pol.Msg.RateLimits,
		ExpectedVersion: pol.Msg.Version,
	})
	withAdmin(env, upReq)
	if _, err := env.client.UpdatePolicy(ctx, upReq); err != nil {
		t.Fatalf("UpdatePolicy adding a global turnstile:* deny: %v", err)
	}

	lr := connect.NewRequest(&turnstilev1.ListKeysRequest{})
	withAdmin(env, lr)
	if _, err := env.client.ListKeys(ctx, lr); err != nil {
		t.Errorf("management must ignore the global ceiling; got: %v", err)
	}
}

// TestRotateKeyOverWire: rotation invalidates the old token, issues a new one,
// and preserves the id.
func TestRotateKeyOverWire(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	k := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "rotate-me", Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:read"}, Resources: []string{"*"}}},
	})
	oldTok := k.PlaintextToken
	if _, err := env.client.Authenticate(ctx, connect.NewRequest(&turnstilev1.AuthenticateRequest{ClientToken: oldTok})); err != nil {
		t.Fatalf("pre-rotate Authenticate: %v", err)
	}

	rr := connect.NewRequest(&turnstilev1.RotateKeyRequest{Id: k.Id})
	withAdmin(env, rr)
	rot, err := env.client.RotateKey(ctx, rr)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if rot.Msg.PlaintextToken == "" || rot.Msg.PlaintextToken == oldTok {
		t.Fatal("RotateKey should return a fresh plaintext token")
	}
	if rot.Msg.Id != k.Id {
		t.Errorf("id changed on rotate: %q vs %q", rot.Msg.Id, k.Id)
	}
	if _, err := env.client.Authenticate(ctx, connect.NewRequest(&turnstilev1.AuthenticateRequest{ClientToken: oldTok})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("old token after rotate: got %v, want Unauthenticated", connect.CodeOf(err))
	}
	if _, err := env.client.Authenticate(ctx, connect.NewRequest(&turnstilev1.AuthenticateRequest{ClientToken: rot.Msg.PlaintextToken})); err != nil {
		t.Errorf("new token should authenticate: %v", err)
	}
}

// TestManagementAuditing: mutations are self-audited on success, and denied
// (PermissionDenied) attempts are audited too; successful reads are not.
func TestManagementAuditing(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Two mutations (create-key) by the admin.
	created := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{Name: "auditee", Statements: allowAll()})
	plain := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "plain", Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:*"}, Resources: []string{"*"}}},
	})

	// A denied attempt (ungranted key doing ListKeys).
	lr := connect.NewRequest(&turnstilev1.ListKeysRequest{})
	withToken(lr, plain.PlaintextToken)
	if _, err := env.client.ListKeys(ctx, lr); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", connect.CodeOf(err))
	}

	// 2 create-key (success) + 1 list-keys (denied) = 3 management audit entries.
	// (The QueryAudit reads below are not themselves audited.)
	waitForAudit(t, env, 3)

	qr := connect.NewRequest(&turnstilev1.QueryAuditRequest{ActionPrefix: "turnstile:", Limit: 50})
	withAdmin(env, qr)
	q, err := env.client.QueryAudit(ctx, qr)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	var createSeen, deniedSeen bool
	for _, e := range q.Msg.Entries {
		if e.Action == "turnstile:create-key" && e.Resource == created.Id && e.ResponseStatus == 200 {
			createSeen = true
		}
		if e.Action == "turnstile:list-keys" && e.ResponseStatus == 403 {
			deniedSeen = true
		}
	}
	if !createSeen {
		t.Error("expected an audited turnstile:create-key mutation for the created key")
	}
	if !deniedSeen {
		t.Error("expected an audited denied turnstile:list-keys attempt (status 403)")
	}
}

// TestHostRPCsOpen: host-facing RPCs need no credential (SERVICE_CREDENTIAL is
// gone) — Check with no auth header returns a decision rather than erroring.
func TestHostRPCsOpen(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	resp, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: "tsk_bogus", Action: "svc:read", Resources: []string{"svc:x"},
	}))
	if err != nil {
		t.Fatalf("Check without a credential should not error: %v", err)
	}
	if resp.Msg.Decision != turnstilev1.Decision_UNAUTHENTICATED {
		t.Errorf("bogus token: got %v, want UNAUTHENTICATED", resp.Msg.Decision)
	}
}

// TestGenericAuthFailureIndistinguishable is the core security invariant: an
// unknown, a disabled, and an expired key must all yield exactly the same
// UNAUTHENTICATED result over Check, and a generic Unauthenticated over
// Authenticate — no signal distinguishing "no such token" from a real but
// disabled/expired one.
func TestGenericAuthFailureIndistinguishable(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	disabled := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "disabled", Disabled: true, Statements: allowAll(),
	})
	expired := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "expired", Statements: allowAll(),
		ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
	})

	tokens := map[string]string{
		"unknown":  "tsk_does_not_exist",
		"disabled": disabled.PlaintextToken,
		"expired":  expired.PlaintextToken,
	}
	for label, tok := range tokens {
		resp, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
			ClientToken: tok, Action: "svc:read", Resources: []string{"svc:thing:1"}, CountRateLimit: true,
		}))
		if err != nil {
			t.Fatalf("%s: Check returned transport error: %v", label, err)
		}
		m := resp.Msg
		// Identical shape for every failure kind: not allowed, UNAUTHENTICATED,
		// no principal leaked, no rate-limit detail.
		if m.Allowed || m.Decision != turnstilev1.Decision_UNAUTHENTICATED {
			t.Errorf("%s: got allowed=%v decision=%v, want UNAUTHENTICATED", label, m.Allowed, m.Decision)
		}
		if m.Principal != nil {
			t.Errorf("%s: principal must not be set on an auth failure, got %+v", label, m.Principal)
		}
		if m.RateLimit.GetLimited() {
			t.Errorf("%s: rate-limit detail must not leak on an auth failure", label)
		}

		// Authenticate: generic Unauthenticated for all three.
		if _, aerr := env.client.Authenticate(ctx, connect.NewRequest(&turnstilev1.AuthenticateRequest{ClientToken: tok})); connect.CodeOf(aerr) != connect.CodeUnauthenticated {
			t.Errorf("%s: Authenticate code = %v, want Unauthenticated", label, connect.CodeOf(aerr))
		}
	}
}

// TestCheckWritesNoAudit asserts the spec requirement that Check never writes an
// audit entry (hosts report audit afterward via ReportAudit).
func TestCheckWritesNoAudit(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	key := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "k", Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:read"}, Resources: []string{"svc:*"}}},
	})

	for i := 0; i < 5; i++ {
		if _, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
			ClientToken: key.PlaintextToken, Action: "svc:read", Resources: []string{"svc:thing:1"}, CountRateLimit: true,
		})); err != nil {
			t.Fatalf("Check: %v", err)
		}
	}
	// Also a denied and an unauthenticated Check, to be thorough.
	env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{ClientToken: key.PlaintextToken, Action: "svc:write", Resources: []string{"svc:x"}}))
	env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{ClientToken: "tsk_nope", Action: "svc:read", Resources: []string{"svc:x"}}))

	// Give any (erroneous) async write a chance to land, then assert none did.
	time.Sleep(50 * time.Millisecond)
	entries, _, err := env.store.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	// The only entries should be management self-audit (the CreateKey above);
	// Check itself writes nothing.
	var fromCheck int
	for _, e := range entries {
		if e.Method != "MANAGE" {
			fromCheck++
		}
	}
	if fromCheck != 0 {
		t.Errorf("Check must not write audit; found %d non-management entries", fromCheck)
	}
}

// TestGlobalDenyCeilingOverWire proves the deny-only global ceiling overrides a
// key's allow through the real Check path (not just at the Authorizer unit).
func TestGlobalDenyCeilingOverWire(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	key := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "broad", Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:*"}, Resources: []string{"*"}}},
	})

	// Read the current version, then add a global deny for svc:danger.
	getReq := connect.NewRequest(&turnstilev1.GetPolicyRequest{})
	withAdmin(env, getReq)
	pol, err := env.client.GetPolicy(ctx, getReq)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	upReq := connect.NewRequest(&turnstilev1.UpdatePolicyRequest{
		Statements:      []*turnstilev1.Statement{{Effect: turnstilev1.Effect_DENY, Actions: []string{"svc:danger"}, Resources: []string{"*"}}},
		RateLimits:      pol.Msg.RateLimits,
		ExpectedVersion: pol.Msg.Version,
	})
	withAdmin(env, upReq)
	if _, err := env.client.UpdatePolicy(ctx, upReq); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}

	// svc:danger is denied by the ceiling despite the key's svc:* allow.
	danger, _ := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: key.PlaintextToken, Action: "svc:danger", Resources: []string{"svc:x"},
	}))
	if danger.Msg.Allowed || danger.Msg.Decision != turnstilev1.Decision_POLICY_DENIED {
		t.Errorf("svc:danger should be POLICY_DENIED by the ceiling, got %+v", danger.Msg)
	}
	// A sibling action the key allows is still permitted.
	ok, _ := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
		ClientToken: key.PlaintextToken, Action: "svc:read", Resources: []string{"svc:x"},
	}))
	if !ok.Msg.Allowed {
		t.Errorf("svc:read should still be allowed, got %+v", ok.Msg)
	}
}

// TestUpdateKeySemantics covers partial-update "leave unchanged", statement
// replacement, and the expires_at/clear_expiry mutual exclusion.
func TestUpdateKeySemantics(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	future := timestamppb.New(time.Now().Add(24 * time.Hour))
	key := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "orig", Note: "n1", ExpiresAt: future,
		Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:read"}, Resources: []string{"svc:*"}}},
	})

	update := func(r *turnstilev1.UpdateKeyRequest) (*turnstilev1.Key, error) {
		r.Id = key.Id
		req := connect.NewRequest(r)
		withAdmin(env, req)
		resp, err := env.client.UpdateKey(ctx, req)
		if err != nil {
			return nil, err
		}
		return resp.Msg, nil
	}

	// expires_at + clear_expiry together is rejected.
	if _, err := update(&turnstilev1.UpdateKeyRequest{ExpiresAt: future, ClearExpiry: true}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("expires_at + clear_expiry should be InvalidArgument, got %v", connect.CodeOf(err))
	}

	// Update only the note; name, statements, and expiry stay unchanged.
	newNote := "n2"
	got, err := update(&turnstilev1.UpdateKeyRequest{Note: &newNote})
	if err != nil {
		t.Fatalf("update note: %v", err)
	}
	if got.Note != "n2" || got.Name != "orig" || len(got.Statements) != 1 || got.ExpiresAt == nil {
		t.Errorf("partial update changed unintended fields: %+v", got)
	}

	// Replace statements.
	got, err = update(&turnstilev1.UpdateKeyRequest{
		Statements: &turnstilev1.StatementList{Statements: []*turnstilev1.Statement{
			{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:write"}, Resources: []string{"svc:*"}},
		}},
	})
	if err != nil {
		t.Fatalf("replace statements: %v", err)
	}
	if len(got.Statements) != 1 || got.Statements[0].Actions[0] != "svc:write" {
		t.Errorf("statements not replaced: %+v", got.Statements)
	}

	// Clear the expiry.
	got, err = update(&turnstilev1.UpdateKeyRequest{ClearExpiry: true})
	if err != nil {
		t.Fatalf("clear expiry: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Errorf("expiry should be cleared, got %v", got.ExpiresAt)
	}

	// Set per-action rate-limit overrides (a bare action→limit map).
	got, err = update(&turnstilev1.UpdateKeyRequest{
		RateLimits: map[string]*turnstilev1.Limit{"svc:write": {PerMinute: 30}},
	})
	if err != nil {
		t.Fatalf("set rate limits: %v", err)
	}
	if l, ok := got.RateLimits["svc:write"]; !ok || l.PerMinute != 30 {
		t.Errorf("rate limit override not applied: %+v", got.RateLimits)
	}

	// rate_limits + clear_rate_limits together is rejected.
	if _, err := update(&turnstilev1.UpdateKeyRequest{
		RateLimits:      map[string]*turnstilev1.Limit{"svc:write": {PerMinute: 10}},
		ClearRateLimits: true,
	}); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("rate_limits + clear_rate_limits should be InvalidArgument, got %v", connect.CodeOf(err))
	}

	// Clear the rate-limit overrides.
	got, err = update(&turnstilev1.UpdateKeyRequest{ClearRateLimits: true})
	if err != nil {
		t.Fatalf("clear rate limits: %v", err)
	}
	if len(got.RateLimits) != 0 {
		t.Errorf("rate limits should be cleared, got %+v", got.RateLimits)
	}
}

// TestConcurrentCheckAndPolicyUpdate races many Check reads against repeated
// UpdatePolicy writes, exercising the shared PolicyCache and rate-limiter
// mutation on the hot path. Meant to be run under `go test -race`.
func TestConcurrentCheckAndPolicyUpdate(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	key := mustCreateKey(t, env, &turnstilev1.CreateKeyRequest{
		Name: "broad", Statements: []*turnstilev1.Statement{{Effect: turnstilev1.Effect_ALLOW, Actions: []string{"svc:*"}, Resources: []string{"*"}}},
	})

	var wg sync.WaitGroup
	// Concurrent readers on the hot path.
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := env.client.Check(ctx, connect.NewRequest(&turnstilev1.CheckRequest{
					ClientToken: key.PlaintextToken, Action: "svc:read", Resources: []string{"svc:x"}, CountRateLimit: true,
				})); err != nil {
					t.Errorf("Check: %v", err)
					return
				}
			}
		}()
	}
	// Concurrent policy writer: read-then-update, tolerating version conflicts.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			getReq := connect.NewRequest(&turnstilev1.GetPolicyRequest{})
			withAdmin(env, getReq)
			pol, err := env.client.GetPolicy(ctx, getReq)
			if err != nil {
				t.Errorf("GetPolicy: %v", err)
				return
			}
			upReq := connect.NewRequest(&turnstilev1.UpdatePolicyRequest{
				Statements:      []*turnstilev1.Statement{{Effect: turnstilev1.Effect_DENY, Actions: []string{"svc:danger"}, Resources: []string{"*"}}},
				RateLimits:      pol.Msg.RateLimits,
				ExpectedVersion: pol.Msg.Version,
			})
			withAdmin(env, upReq)
			// A concurrent update may have bumped the version; Aborted is fine.
			if _, err := env.client.UpdatePolicy(ctx, upReq); err != nil && connect.CodeOf(err) != connect.CodeAborted {
				t.Errorf("UpdatePolicy: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

func waitForAudit(t *testing.T, env *testEnv, want int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		entries, _, err := env.store.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatalf("list audit: %v", err)
		}
		if len(entries) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("audit entries did not reach %d in time", want)
}

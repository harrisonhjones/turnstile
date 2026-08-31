package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/ratelimit"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAPIKeyCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	k := &APIKey{
		ID:         "key_1",
		Name:       "alpha",
		KeyHash:    "hash1",
		Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"svc:read"}, Resources: []string{"*"}}},
		RateLimits: ratelimit.PerActionLimits{"svc:read": {PerMinute: 10}},
		Note:       "a note",
		CreatedAt:  now,
	}
	if err := s.CreateAPIKey(ctx, k); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.GetAPIKeyByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.Name != "alpha" || got.Note != "a note" || len(got.Statements) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if l, ok := got.RateLimits["svc:read"]; !ok || l.PerMinute != 10 {
		t.Errorf("rate limits not preserved: %+v", got.RateLimits)
	}

	// Duplicate name is rejected.
	dup := *k
	dup.ID = "key_2"
	dup.KeyHash = "hash2"
	if err := s.CreateAPIKey(ctx, &dup); !errors.Is(err, ErrNameTaken) {
		t.Errorf("expected ErrNameTaken, got %v", err)
	}

	// Partial update.
	updated, err := s.UpdateAPIKeyFunc(ctx, "key_1", func(k *APIKey) error {
		k.Disabled = true
		k.Note = "updated"
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !updated.Disabled || updated.Note != "updated" {
		t.Errorf("update not applied: %+v", updated)
	}

	// List excludes disabled by default.
	active, err := s.ListAPIKeys(ctx, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("expected 0 active keys, got %d", len(active))
	}
	all, _ := s.ListAPIKeys(ctx, true)
	if len(all) != 1 {
		t.Errorf("expected 1 key including disabled, got %d", len(all))
	}

	if err := s.DeleteAPIKey(ctx, "key_1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteAPIKey(ctx, "key_1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on second delete, got %v", err)
	}
}

// TestAPIKeyTimestampsSubSecond verifies key timestamps round-trip at
// nanosecond precision and that ListAPIKeys orders by created_at
// chronologically even for keys created within the same second (the epoch-nanos
// INTEGER storage removes the RFC3339 TEXT lexical-ordering hazard).
func TestAPIKeyTimestampsSubSecond(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	whole := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)           // 12:00:00.000
	half := time.Date(2026, 6, 1, 12, 0, 0, 500_000_000, time.UTC)  // 12:00:00.500
	expiry := time.Date(2026, 7, 1, 9, 8, 7, 123_456_789, time.UTC) // sub-second expiry

	// "older" is at the whole second, "newer" 500ms later in the same second —
	// the exact case lexical RFC3339 sorting got wrong.
	older := &APIKey{ID: "k_old", Name: "older", KeyHash: "h_old", CreatedAt: whole, ExpiresAt: &expiry,
		Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"a"}, Resources: []string{"b"}}}}
	newer := &APIKey{ID: "k_new", Name: "newer", KeyHash: "h_new", CreatedAt: half,
		Statements: []policy.Statement{{Effect: policy.Allow, Actions: []string{"a"}, Resources: []string{"b"}}}}
	if err := s.CreateAPIKey(ctx, older); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(ctx, newer); err != nil {
		t.Fatal(err)
	}

	// Nanosecond-precision round-trip.
	got, err := s.GetAPIKeyByID(ctx, "k_old")
	if err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(whole) {
		t.Errorf("created_at round-trip: got %v want %v", got.CreatedAt, whole)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expiry) {
		t.Errorf("expires_at round-trip: got %v want %v", got.ExpiresAt, expiry)
	}

	// ORDER BY created_at DESC must be chronological: newer (.500) before older (.000).
	keys, err := s.ListAPIKeys(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].ID != "k_new" || keys[1].ID != "k_old" {
		t.Errorf("expected newest-first [k_new, k_old], got %v", []string{keys[0].ID, keys[1].ID})
	}
}

func TestGlobalPolicyVersioning(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	gp := &GlobalPolicy{
		Version:    1,
		Statements: []policy.Statement{},
		Constraints: Constraints{RateLimits: ratelimit.Global{
			PerKey: ratelimit.Config{Default: &ratelimit.Limit{PerMinute: 100}},
		}},
		UpdatedAt: now,
		UpdatedBy: "bootstrap",
	}
	if err := s.UpsertGlobalPolicy(ctx, gp); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Update with correct version succeeds and bumps to 2.
	next := &GlobalPolicy{
		Statements: []policy.Statement{{Effect: policy.Deny, Actions: []string{"svc:danger"}, Resources: []string{"*"}}},
		UpdatedAt:  now,
		UpdatedBy:  "admin",
	}
	if err := s.UpdateGlobalPolicy(ctx, next, 1); err != nil {
		t.Fatalf("update v1: %v", err)
	}
	if next.Version != 2 {
		t.Errorf("expected version 2, got %d", next.Version)
	}

	// Stale version is rejected.
	stale := &GlobalPolicy{Statements: []policy.Statement{}, UpdatedAt: now}
	if err := s.UpdateGlobalPolicy(ctx, stale, 1); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("expected ErrVersionConflict, got %v", err)
	}

	loaded, err := s.GetGlobalPolicy(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if loaded.Version != 2 || len(loaded.Statements) != 1 || loaded.UpdatedBy != "admin" {
		t.Errorf("loaded policy mismatch: %+v", loaded)
	}
}

func TestRotateAPIKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	k := &APIKey{ID: "turnstile:key:abc", Name: "k", KeyHash: "h1", Statements: []policy.Statement{}, CreatedAt: time.Now()}
	if err := s.CreateAPIKey(ctx, k); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.RotateAPIKey(ctx, k.ID, "h2")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got.KeyHash != "h2" {
		t.Errorf("hash not rotated: %q", got.KeyHash)
	}
	// Old hash no longer resolves; new one does.
	if _, err := s.GetAPIKeyByHash(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old hash should not resolve, got %v", err)
	}
	if _, err := s.GetAPIKeyByHash(ctx, "h2"); err != nil {
		t.Errorf("new hash should resolve, got %v", err)
	}
	if _, err := s.RotateAPIKey(ctx, "turnstile:key:missing", "h3"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound rotating a missing key, got %v", err)
	}
}

func TestAuditInsertAndQuery(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	entries := []*AuditEntry{
		{Timestamp: base.Add(1 * time.Second), APIKeyID: "k1", Action: "beeper:read", Resource: "beeper:a", Decision: "ALLOWED"},
		{Timestamp: base.Add(2 * time.Second), APIKeyID: "k1", Action: "beeper:send", Resource: "beeper:b", Decision: "POLICY_DENIED"},
		{Timestamp: base.Add(3 * time.Second), APIKeyID: "k2", Action: "plaid:read", Resource: "plaid:c", Decision: "ALLOWED"},
	}
	for _, e := range entries {
		if err := s.InsertAuditEntry(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Filter by key.
	byKey, _, err := s.ListAuditEntries(ctx, AuditFilter{APIKeyID: "k1", Limit: 10})
	if err != nil {
		t.Fatalf("query by key: %v", err)
	}
	if len(byKey) != 2 {
		t.Errorf("expected 2 entries for k1, got %d", len(byKey))
	}

	// Filter by action-namespace prefix.
	byNS, _, _ := s.ListAuditEntries(ctx, AuditFilter{ActionPrefix: "beeper:", Limit: 10})
	if len(byNS) != 2 {
		t.Errorf("expected 2 beeper: entries, got %d", len(byNS))
	}

	// Filter by decision.
	byDecision, _, _ := s.ListAuditEntries(ctx, AuditFilter{Decision: "POLICY_DENIED", Limit: 10})
	if len(byDecision) != 1 {
		t.Errorf("expected 1 POLICY_DENIED entry, got %d", len(byDecision))
	}

	// Keyset pagination newest-first.
	page1, cursor, _ := s.ListAuditEntries(ctx, AuditFilter{Limit: 2})
	if len(page1) != 2 || cursor == 0 {
		t.Fatalf("expected full page + cursor, got %d entries cursor=%d", len(page1), cursor)
	}
	if page1[0].Action != "plaid:read" {
		t.Errorf("expected newest entry first, got %q", page1[0].Action)
	}
	page2, cursor2, _ := s.ListAuditEntries(ctx, AuditFilter{Limit: 2, Cursor: cursor})
	if len(page2) != 1 || cursor2 != 0 {
		t.Errorf("expected final page of 1 with no cursor, got %d entries cursor=%d", len(page2), cursor2)
	}
}

// TestAuditTimeRangeSubSecond is the H1 regression: time-range filters must be
// correct at sub-second boundaries. With the previous RFC3339Nano TEXT storage,
// "12:00:00.000Z" sorted lexically AFTER "12:00:00.500Z", so an `after` bound of
// .500 wrongly included the .000 entry. Epoch-nanos INTEGER storage fixes it.
func TestAuditTimeRangeSubSecond(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	whole := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)        // 12:00:00.000
	half := time.Date(2026, 6, 1, 12, 0, 0, 500000000, time.UTC) // 12:00:00.500
	later := time.Date(2026, 6, 1, 12, 0, 1, 0, time.UTC)        // 12:00:01.000

	for _, ts := range []time.Time{whole, half, later} {
		if err := s.InsertAuditEntry(ctx, &AuditEntry{
			Timestamp: ts, APIKeyID: "k", Action: "svc:read", Resource: "svc:x", Decision: "ALLOWED",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// after = 12:00:00.500 must EXCLUDE the .000 entry and include .500 and 01.000.
	afterHalf := half
	got, _, err := s.ListAuditEntries(ctx, AuditFilter{After: &afterHalf, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("after=.500 should match 2 entries (.500, 01.000), got %d", len(got))
	}
	for _, e := range got {
		if e.Timestamp.Before(half) {
			t.Errorf("after=.500 wrongly included %v (before the bound)", e.Timestamp)
		}
	}

	// before = 12:00:00.500 must include .000 and .500, exclude 01.000.
	beforeHalf := half
	got2, _, _ := s.ListAuditEntries(ctx, AuditFilter{Before: &beforeHalf, Limit: 10})
	if len(got2) != 2 {
		t.Fatalf("before=.500 should match 2 entries (.000, .500), got %d", len(got2))
	}
	for _, e := range got2 {
		if e.Timestamp.After(half) {
			t.Errorf("before=.500 wrongly included %v (after the bound)", e.Timestamp)
		}
	}
}

// TestAutoVacuumEnabled verifies the DB is created with incremental auto_vacuum
// (mode 2) so retention's IncrementalVacuum can reclaim freed pages.
func TestAutoVacuumEnabled(t *testing.T) {
	s := newTestStore(t)
	var mode int
	if err := s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		t.Fatalf("read auto_vacuum: %v", err)
	}
	if mode != 2 {
		t.Errorf("auto_vacuum = %d, want 2 (INCREMENTAL)", mode)
	}
	if err := s.IncrementalVacuum(context.Background()); err != nil {
		t.Errorf("IncrementalVacuum: %v", err)
	}
}

// TestAuditLikeEscaping verifies that LIKE metacharacters in the action-prefix
// filter are matched literally rather than acting as wildcards.
func TestAuditLikeEscaping(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	actions := []string{"a%b", "axb", "a_b", "acb"}
	for i, a := range actions {
		if err := s.InsertAuditEntry(ctx, &AuditEntry{
			Timestamp: base.Add(time.Duration(i) * time.Second), APIKeyID: "k",
			Action: a, Resource: "r", Decision: "ALLOWED",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// "a%" as a literal prefix should match only "a%b", NOT "axb".
	got, _, err := s.ListAuditEntries(ctx, AuditFilter{ActionPrefix: "a%", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Action != "a%b" {
		t.Errorf(`ActionPrefix "a%%" should match only "a%%b", got %d entries`, len(got))
	}

	// "a_" should match only "a_b", NOT "acb".
	got2, _, _ := s.ListAuditEntries(ctx, AuditFilter{ActionPrefix: "a_", Limit: 10})
	if len(got2) != 1 || got2[0].Action != "a_b" {
		t.Errorf(`ActionPrefix "a_" should match only "a_b", got %d entries`, len(got2))
	}
}

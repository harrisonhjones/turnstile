package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"harrisonhjones.com/turnstile/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func entry(id string) *store.AuditEntry {
	return &store.AuditEntry{
		Timestamp: time.Now(), APIKeyID: id, APIKeyName: "n", Method: "REST",
		Path: "/p", Action: "svc:read", ResponseStatus: 200,
	}
}

func countAudit(t *testing.T, s *store.Store) int {
	t.Helper()
	es, _, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	return len(es)
}

// TestWriterPersistsAndDrains verifies queued entries are persisted, and that
// Wait drains the buffer before returning (nothing enqueued before Wait is lost).
func TestWriterPersistsAndDrains(t *testing.T) {
	s := newTestStore(t)
	w := NewWriter(s)

	const n = 20
	for i := 0; i < n; i++ {
		if !w.Write(entry("k")) {
			t.Fatalf("Write %d should be accepted", i)
		}
	}
	w.Wait() // must block until the consumer has drained all buffered entries

	if got := countAudit(t, s); got != n {
		t.Errorf("persisted %d entries, want %d", got, n)
	}
}

// TestWriterDropsAfterStopping verifies that once Wait has begun shutdown, Write
// deterministically drops (returns false) rather than enqueuing into a channel
// whose consumer has exited.
func TestWriterDropsAfterStopping(t *testing.T) {
	s := newTestStore(t)
	w := NewWriter(s)
	w.Wait() // signals stopping and drains

	if w.Write(entry("k")) {
		t.Error("Write after Wait should be dropped (return false)")
	}
	if got := countAudit(t, s); got != 0 {
		t.Errorf("no entries should have been persisted, got %d", got)
	}
	// Wait is idempotent.
	w.Wait()
}

// TestRunRetentionPrunes verifies the retention loop deletes entries older than
// the window on its immediate first pass.
func TestRunRetentionPrunes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// One entry two days old (should be pruned with a 1-day window) and one now.
	if err := s.InsertAuditEntry(ctx, &store.AuditEntry{Timestamp: now.AddDate(0, 0, -2), APIKeyID: "old", APIKeyName: "n", Method: "REST", Path: "/p", ResponseStatus: 200}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAuditEntry(ctx, &store.AuditEntry{Timestamp: now, APIKeyID: "new", APIKeyName: "n", Method: "REST", Path: "/p", ResponseStatus: 200}); err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go RunRetention(runCtx, s, 1, func() time.Time { return now })

	// RunRetention prunes once immediately; poll until the old entry is gone.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if countAudit(t, s) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retention did not prune the old entry in time (have %d)", countAudit(t, s))
		}
		time.Sleep(10 * time.Millisecond)
	}

	remaining, _, _ := s.ListAuditEntries(ctx, store.AuditFilter{Limit: 10})
	if len(remaining) != 1 || remaining[0].APIKeyID != "new" {
		t.Errorf("expected only the recent entry to survive, got %+v", remaining)
	}
}

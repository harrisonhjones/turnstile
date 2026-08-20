package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/harrisonhjones/turnstile/internal/store"
)

// retentionInterval is how often the retention loop prunes. Audit growth is
// slow relative to a day, so a few times daily keeps the table bounded without
// churn.
const retentionInterval = 6 * time.Hour

// RunRetention periodically deletes audit entries older than retentionDays. It
// prunes once immediately, then every retentionInterval until ctx is cancelled.
// A retentionDays of 0 disables pruning and RunRetention returns immediately.
//
// It is meant to run in its own goroutine for the process lifetime; cancel ctx
// (e.g. on shutdown) to stop it.
func RunRetention(ctx context.Context, s *store.Store, retentionDays int, now func() time.Time) {
	if retentionDays <= 0 {
		slog.Info("audit retention disabled; entries are kept indefinitely")
		return
	}
	slog.Info("audit retention enabled", "days", retentionDays)

	prune := func() {
		cutoff := now().AddDate(0, 0, -retentionDays)
		// Bound each prune so a slow delete can't run unbounded; it retries on
		// the next tick regardless.
		pruneCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		n, err := s.DeleteAuditEntriesBefore(pruneCtx, cutoff)
		if err != nil {
			slog.Error("audit retention prune failed", "error", err)
			return
		}
		if n > 0 {
			slog.Info("pruned old audit entries", "count", n, "olderThan", cutoff.Format(time.RFC3339))
			// Return the freed pages to the OS (no-op unless auto_vacuum is on).
			if err := s.IncrementalVacuum(pruneCtx); err != nil {
				slog.Warn("audit retention incremental_vacuum failed", "error", err)
			}
		}
	}

	prune()

	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}

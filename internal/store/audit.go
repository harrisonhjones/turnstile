package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// escapeLike escapes SQL LIKE metacharacters (%, _, and the escape char itself)
// so a value can be used as a literal prefix with `LIKE ? ESCAPE '\'`.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// AuditEntry is one recorded decision. APIKeyID is empty for an unauthenticated
// Check; Decision is the outcome name (e.g. "ALLOWED", "POLICY_DENIED").
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	APIKeyID  string
	Action    string
	Resource  string
	Decision  string
}

// InsertAuditEntry appends an audit entry.
func (s *Store) InsertAuditEntry(ctx context.Context, e *AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (timestamp, api_key_id, action, resource, decision)
		 VALUES (?, ?, ?, ?, ?)`,
		nanos(e.Timestamp), e.APIKeyID, e.Action, e.Resource, e.Decision,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// DeleteAuditEntriesBefore removes audit entries older than cutoff and returns
// the number deleted. Used by the retention cleanup; SQLite has no built-in row
// TTL, so pruning is an explicit periodic DELETE.
func (s *Store) DeleteAuditEntriesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM audit_log WHERE timestamp < ?`, nanos(cutoff))
	if err != nil {
		return 0, fmt.Errorf("delete audit entries: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit delete rows affected: %w", err)
	}
	return n, nil
}

// AuditFilter narrows an audit query. Zero-value fields are ignored.
type AuditFilter struct {
	APIKeyID     string     // restrict to one key
	ActionPrefix string     // action-namespace prefix (e.g. "photos:" or "turnstile:")
	Decision     string     // exact decision name (e.g. "ALLOWED"); empty = any
	After        *time.Time // entries at or after
	Before       *time.Time // entries at or before
	Limit        int        // page size
	Cursor       int64      // return entries with id < cursor (keyset pagination)
}

// ListAuditEntries returns audit entries newest-first, applying the filter.
// Results use keyset pagination on the descending id; the returned nextCursor
// is the id to pass as Cursor for the following page (0 when exhausted).
func (s *Store) ListAuditEntries(ctx context.Context, f AuditFilter) (entries []*AuditEntry, nextCursor int64, err error) {
	var (
		where []string
		args  []any
	)
	if f.APIKeyID != "" {
		where = append(where, "api_key_id = ?")
		args = append(args, f.APIKeyID)
	}
	if f.ActionPrefix != "" {
		// Prefix match. Escape LIKE metacharacters so a caller-supplied % or _
		// is matched literally rather than acting as a wildcard.
		where = append(where, `action LIKE ? ESCAPE '\'`)
		args = append(args, escapeLike(f.ActionPrefix)+"%")
	}
	if f.Decision != "" {
		where = append(where, "decision = ?")
		args = append(args, f.Decision)
	}
	if f.After != nil {
		where = append(where, "timestamp >= ?")
		args = append(args, nanos(*f.After))
	}
	if f.Before != nil {
		where = append(where, "timestamp <= ?")
		args = append(args, nanos(*f.Before))
	}
	if f.Cursor > 0 {
		where = append(where, "id < ?")
		args = append(args, f.Cursor)
	}

	q := `SELECT id, timestamp, api_key_id, action, resource, decision
	      FROM audit_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	// Fetch one extra row to determine whether another page exists.
	args = append(args, f.Limit+1)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			e       AuditEntry
			tsNanos int64
		)
		if err := rows.Scan(&e.ID, &tsNanos, &e.APIKeyID, &e.Action, &e.Resource, &e.Decision); err != nil {
			return nil, 0, fmt.Errorf("scan audit entry: %w", err)
		}
		e.Timestamp = timeFromNanos(tsNanos)
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// If we got the extra row, there's another page; trim it and expose the
	// cursor (the id of the last returned entry).
	if len(entries) > f.Limit {
		entries = entries[:f.Limit]
		nextCursor = entries[len(entries)-1].ID
	}
	return entries, nextCursor, nil
}

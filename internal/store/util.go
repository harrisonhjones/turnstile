package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// ErrNameTaken is returned when a create/update would violate a unique name
// constraint (api_keys.name or admin_credentials.name).
var ErrNameTaken = errors.New("name already in use")

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint failure.
// The driver may report either the primary code (SQLITE_CONSTRAINT) or an
// extended code (SQLITE_CONSTRAINT_UNIQUE); the low byte holds the primary
// code, so masking catches both.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	return se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// Times are stored as RFC3339 strings in UTC for stable, sortable text.

func formatTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time %q: %w", s, err)
	}
	return t, nil
}

func parseNullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

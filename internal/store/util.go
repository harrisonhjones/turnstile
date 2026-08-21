package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// ErrNameTaken is returned when a create/update would violate a unique name
// constraint (api_keys.name or admin_credentials.name).
var ErrNameTaken = errors.New("name already in use")

// isUniqueViolation reports whether err is specifically a SQLite UNIQUE
// constraint failure — not any constraint (NOT NULL, CHECK, FK, PK all share the
// primary SQLITE_CONSTRAINT code, so masking the low byte would misclassify
// those as name collisions). We match the extended code SQLITE_CONSTRAINT_UNIQUE
// (and SQLITE_CONSTRAINT_PRIMARYKEY, which a duplicate id would raise), with a
// message-substring fallback in case the driver reports only the primary code.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// All timestamps are stored as epoch nanoseconds (INTEGER). Integer comparison
// orders chronologically without the lexical hazards of RFC3339 TEXT (trailing-
// zero fractions), and every table shares one representation.

// nanos encodes a non-null timestamp column.
func nanos(t time.Time) int64 { return t.UTC().UnixNano() }

// nullableNanos encodes a nullable timestamp column: nil → SQL NULL.
func nullableNanos(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().UnixNano()
}

// timeFromNanos decodes a non-null timestamp column.
func timeFromNanos(n int64) time.Time { return time.Unix(0, n).UTC() }

// timeFromNullNanos decodes a nullable timestamp column.
func timeFromNullNanos(ns sql.NullInt64) *time.Time {
	if !ns.Valid {
		return nil
	}
	t := time.Unix(0, ns.Int64).UTC()
	return &t
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

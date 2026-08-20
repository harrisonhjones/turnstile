// Package store provides SQLite-backed persistence for API keys, admin
// credentials, the global service policy, and the audit log. It uses the
// pure-Go modernc.org/sqlite driver (no CGO).
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// connectionPragmas are applied to every pooled connection via the DSN. Setting
// them through the DSN (rather than a one-off Exec) is important because
// database/sql maintains a connection pool: busy_timeout and foreign_keys are
// per-connection settings, so a startup Exec would only configure whichever
// single connection served it. journal_mode=WAL is database-level and persists
// to the file, but is included for completeness. busy_timeout makes concurrent
// writers wait rather than fail with SQLITE_BUSY.
var connectionPragmas = []string{
	// auto_vacuum must be set before any table is created to take effect on a
	// fresh database (it is applied on every connect, which for a new file
	// happens before the schema runs); on an existing populated DB it is a
	// silent no-op without a full VACUUM. INCREMENTAL lets retention reclaim
	// freed pages via PRAGMA incremental_vacuum (see IncrementalVacuum) rather
	// than leaving the file at its high-water mark after old rows are pruned.
	"auto_vacuum(INCREMENTAL)",
	"busy_timeout(5000)",
	"foreign_keys(on)",
	"journal_mode(WAL)",
}

// Store wraps the SQLite database connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path, applies the
// schema, and enables WAL mode plus a busy timeout for read/write concurrency.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

// dsn builds a modernc.org/sqlite DSN that applies connectionPragmas to every
// pooled connection. It preserves a caller-supplied query string (e.g. a test
// using ":memory:" or file: URIs with existing params).
func dsn(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	parts := make([]string, 0, len(connectionPragmas)+1)
	for _, p := range connectionPragmas {
		parts = append(parts, "_pragma="+url.QueryEscape(p))
	}
	// Use BEGIN IMMEDIATE for explicit transactions so a read-then-write tx
	// (see UpdateAPIKeyFunc) takes the write lock up front, avoiding the
	// deadlock two deferred transactions would hit when both try to upgrade a
	// read lock to a write lock.
	parts = append(parts, "_txlock=immediate")
	return path + sep + strings.Join(parts, "&")
}

// IncrementalVacuum returns freed pages to the OS. It is a no-op unless the
// database was created with auto_vacuum=INCREMENTAL. Called after a retention
// prune so deleting old rows actually shrinks the file rather than just marking
// pages free for reuse.
func (s *Store) IncrementalVacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return fmt.Errorf("incremental_vacuum: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

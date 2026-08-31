// Package store provides SQLite-backed persistence for API keys, the global
// service policy, and the audit log. It uses the pure-Go modernc.org/sqlite
// driver (no CGO).
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

	// Migrate any pre-existing DB to the current schema shape BEFORE the
	// CREATE TABLE IF NOT EXISTS below (which is a no-op for tables that already
	// exist and so can't reshape them on its own).
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return &Store{db: db}, nil
}

// schemaVersion is the current on-disk schema generation, tracked in SQLite's
// PRAGMA user_version. Bump it and add a migration step whenever a released
// schema change isn't achievable via CREATE TABLE IF NOT EXISTS alone.
const schemaVersion = 1

// migrate brings an existing database up to schemaVersion. A fresh database
// (user_version 0, no tables) passes through untouched — Open's schema apply
// creates everything. The v0→v1 step handles the self-managed-auth/audit
// reshape: the admin_credentials table was removed, and audit_log was reshaped
// (a decision column added, the old host-reported columns dropped). Because
// those are incompatible with a plain IF NOT EXISTS, drop the dead
// admin_credentials table and rebuild a *legacy* audit_log (one lacking the
// decision column) so the schema recreates it fresh. Old audit rows are
// discarded — acceptable pre-1.0, and their host-reported shape is gone anyway.
// A database already at the new shape is left intact.
func migrate(db *sql.DB) error {
	var uv int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if uv >= schemaVersion {
		return nil
	}

	if _, err := db.Exec(`DROP TABLE IF EXISTS admin_credentials`); err != nil {
		return fmt.Errorf("drop admin_credentials: %w", err)
	}

	// Rebuild audit_log only if it exists in the legacy shape (no decision column).
	var auditExists int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'`,
	).Scan(&auditExists); err != nil {
		return fmt.Errorf("check audit_log: %w", err)
	}
	if auditExists > 0 {
		var hasDecision int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('audit_log') WHERE name='decision'`,
		).Scan(&hasDecision); err != nil {
			return fmt.Errorf("inspect audit_log columns: %w", err)
		}
		if hasDecision == 0 {
			if _, err := db.Exec(`DROP TABLE audit_log`); err != nil {
				return fmt.Errorf("drop legacy audit_log: %w", err)
			}
		}
	}

	// user_version takes no bind parameters; schemaVersion is a trusted constant.
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return nil
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

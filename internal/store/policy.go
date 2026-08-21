package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/harrisonhjones/turnstile/internal/policy"
	"github.com/harrisonhjones/turnstile/internal/ratelimit"
)

// GlobalPolicy is the singleton service policy.
type GlobalPolicy struct {
	Version     int
	Statements  []policy.Statement
	Constraints Constraints
	UpdatedAt   time.Time
	UpdatedBy   string
}

// Constraints holds policy-level limits that aren't expressible as
// action/resource statements. Currently just request rate limits.
type Constraints struct {
	// RateLimits configures per-key defaults and service-wide request rate limits.
	RateLimits ratelimit.Global `json:"rateLimits"`
}

// GetGlobalPolicy returns the singleton policy. If none exists yet, returns
// ErrNotFound so the caller can seed a default.
func (s *Store) GetGlobalPolicy(ctx context.Context) (*GlobalPolicy, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT version, statements, constraints, updated_at, updated_by
		 FROM global_policy WHERE id = 1`)

	var (
		gp             GlobalPolicy
		statementsRaw  string
		constraintsRaw string
		updatedAt      int64
		updatedBy      sql.NullString
	)
	err := row.Scan(&gp.Version, &statementsRaw, &constraintsRaw, &updatedAt, &updatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan global policy: %w", err)
	}

	if err := json.Unmarshal([]byte(statementsRaw), &gp.Statements); err != nil {
		return nil, fmt.Errorf("unmarshal statements: %w", err)
	}
	if err := json.Unmarshal([]byte(constraintsRaw), &gp.Constraints); err != nil {
		return nil, fmt.Errorf("unmarshal constraints: %w", err)
	}
	gp.UpdatedAt = timeFromNanos(updatedAt)
	gp.UpdatedBy = updatedBy.String
	return &gp, nil
}

// UpsertGlobalPolicy writes the singleton policy, replacing any existing row.
func (s *Store) UpsertGlobalPolicy(ctx context.Context, gp *GlobalPolicy) error {
	stmts, err := json.Marshal(gp.Statements)
	if err != nil {
		return fmt.Errorf("marshal statements: %w", err)
	}
	cons, err := json.Marshal(gp.Constraints)
	if err != nil {
		return fmt.Errorf("marshal constraints: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO global_policy (id, version, statements, constraints, updated_at, updated_by)
		 VALUES (1, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   version = excluded.version,
		   statements = excluded.statements,
		   constraints = excluded.constraints,
		   updated_at = excluded.updated_at,
		   updated_by = excluded.updated_by`,
		gp.Version, string(stmts), string(cons),
		nanos(gp.UpdatedAt), nullString(gp.UpdatedBy),
	)
	if err != nil {
		return fmt.Errorf("upsert global policy: %w", err)
	}
	return nil
}

// ErrVersionConflict is returned by UpdateGlobalPolicy when the caller's
// expected version does not match the stored version (optimistic concurrency).
var ErrVersionConflict = errors.New("policy version conflict")

// UpdateGlobalPolicy replaces the policy only if the currently stored version
// equals expectedVersion, then bumps the stored version to expectedVersion+1.
// The gp.Version field is ignored for the compare and set to the new version on
// success. Returns ErrVersionConflict if the stored version differs (including
// when no policy row exists yet), and ErrNotFound is never returned here.
func (s *Store) UpdateGlobalPolicy(ctx context.Context, gp *GlobalPolicy, expectedVersion int) error {
	stmts, err := json.Marshal(gp.Statements)
	if err != nil {
		return fmt.Errorf("marshal statements: %w", err)
	}
	cons, err := json.Marshal(gp.Constraints)
	if err != nil {
		return fmt.Errorf("marshal constraints: %w", err)
	}

	newVersion := expectedVersion + 1
	res, err := s.db.ExecContext(ctx,
		`UPDATE global_policy SET
		   version = ?, statements = ?, constraints = ?, updated_at = ?, updated_by = ?
		 WHERE id = 1 AND version = ?`,
		newVersion, string(stmts), string(cons),
		nanos(gp.UpdatedAt), nullString(gp.UpdatedBy), expectedVersion,
	)
	if err != nil {
		return fmt.Errorf("update global policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update global policy rows affected: %w", err)
	}
	if n == 0 {
		return ErrVersionConflict
	}
	gp.Version = newVersion
	return nil
}

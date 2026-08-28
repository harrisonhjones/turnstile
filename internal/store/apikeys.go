package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"harrisonhjones.com/turnstile/internal/policy"
	"harrisonhjones.com/turnstile/internal/ratelimit"
)

// APIKey is a stored API key (a client token). The plaintext token is never
// persisted.
type APIKey struct {
	ID         string
	Name       string
	KeyHash    string
	Statements []policy.Statement
	RateLimits ratelimit.PerActionLimits
	Note       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	Disabled   bool
}

// Expired reports whether the key has an expiry in the past relative to now.
func (k *APIKey) Expired(now time.Time) bool {
	return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
}

const apiKeyColumns = `id, name, key_hash, statements, rate_limits, note, created_at, last_used_at, expires_at, disabled`

// CreateAPIKey inserts a new API key.
func (s *Store) CreateAPIKey(ctx context.Context, k *APIKey) error {
	stmts, err := json.Marshal(k.Statements)
	if err != nil {
		return fmt.Errorf("marshal statements: %w", err)
	}
	limits, err := json.Marshal(k.RateLimits)
	if err != nil {
		return fmt.Errorf("marshal rate limits: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, name, key_hash, statements, rate_limits, note, created_at, expires_at, disabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.Name, k.KeyHash, string(stmts), string(limits), k.Note,
		nanos(k.CreatedAt), nullableNanos(k.ExpiresAt), boolToInt(k.Disabled),
	)
	if isUniqueViolation(err) {
		return ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("insert api key: %w", err)
	}
	return nil
}

// GetAPIKeyByHash looks up a key by its token hash. Returns ErrNotFound if
// absent.
func (s *Store) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = ?`, hash)
	return scanAPIKey(row)
}

// GetAPIKeyByID looks up a key by its ID. Returns ErrNotFound if absent.
func (s *Store) GetAPIKeyByID(ctx context.Context, id string) (*APIKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE id = ?`, id)
	return scanAPIKey(row)
}

// ListAPIKeys returns keys, optionally including disabled ones.
func (s *Store) ListAPIKeys(ctx context.Context, includeDisabled bool) ([]*APIKey, error) {
	q := `SELECT ` + apiKeyColumns + ` FROM api_keys`
	if !includeDisabled {
		q += ` WHERE disabled = 0`
	}
	q += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query api keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// CountAPIKeys returns the total number of API keys (including disabled).
func (s *Store) CountAPIKeys(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count api keys: %w", err)
	}
	return n, nil
}

// UpdateAPIKeyFunc atomically applies a partial update to a key. It loads the
// key, invokes mutate to apply changes in memory, then writes it back — all in
// a single write transaction (BEGIN IMMEDIATE), which SQLite serializes against
// other writers. This closes the read-modify-write lost-update window that a
// separate GetAPIKeyByID + UpdateAPIKey would leave open when two updates race.
//
// mutate receives the current key and should apply the request's changes; if it
// returns an error, the transaction rolls back and that error is returned
// (letting the handler surface validation failures). Returns ErrNotFound if the
// key does not exist and ErrNameTaken on a unique-name violation.
func (s *Store) UpdateAPIKeyFunc(ctx context.Context, id string, mutate func(*APIKey) error) (*APIKey, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE id = ?`, id)
	key, err := scanAPIKey(row)
	if err != nil {
		return nil, err // ErrNotFound or scan error
	}

	if err := mutate(key); err != nil {
		return nil, err
	}

	stmts, err := json.Marshal(key.Statements)
	if err != nil {
		return nil, fmt.Errorf("marshal statements: %w", err)
	}
	limits, err := json.Marshal(key.RateLimits)
	if err != nil {
		return nil, fmt.Errorf("marshal rate limits: %w", err)
	}
	_, err = tx.ExecContext(ctx,
		`UPDATE api_keys SET name = ?, statements = ?, rate_limits = ?, note = ?, expires_at = ?, disabled = ?
		 WHERE id = ?`,
		key.Name, string(stmts), string(limits), key.Note,
		nullableNanos(key.ExpiresAt), boolToInt(key.Disabled), key.ID,
	)
	if isUniqueViolation(err) {
		return nil, ErrNameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("update api key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return key, nil
}

// DeleteAPIKey removes a key by ID. Returns ErrNotFound if no row was deleted.
func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete api key rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed updates last_used_at for a key to the given time.
func (s *Store) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, nanos(at), id)
	return err
}

func scanAPIKey(sc scanner) (*APIKey, error) {
	var (
		k             APIKey
		statementsRaw string
		rateLimitsRaw string
		createdAt     int64
		lastUsedAt    sql.NullInt64
		expiresAt     sql.NullInt64
		disabled      int
	)
	err := sc.Scan(&k.ID, &k.Name, &k.KeyHash, &statementsRaw, &rateLimitsRaw, &k.Note,
		&createdAt, &lastUsedAt, &expiresAt, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan api key: %w", err)
	}

	if err := json.Unmarshal([]byte(statementsRaw), &k.Statements); err != nil {
		return nil, fmt.Errorf("unmarshal statements: %w", err)
	}
	if rateLimitsRaw != "" {
		if err := json.Unmarshal([]byte(rateLimitsRaw), &k.RateLimits); err != nil {
			return nil, fmt.Errorf("unmarshal rate limits: %w", err)
		}
	}
	k.CreatedAt = timeFromNanos(createdAt)
	k.LastUsedAt = timeFromNullNanos(lastUsedAt)
	k.ExpiresAt = timeFromNullNanos(expiresAt)
	k.Disabled = disabled != 0
	return &k, nil
}

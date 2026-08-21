package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AdminCredential is a stored management credential. Only its SHA-256 hash is
// persisted, never the plaintext.
type AdminCredential struct {
	ID         string
	Name       string
	CredHash   string
	Note       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

const adminColumns = `id, name, cred_hash, note, created_at, last_used_at`

// CreateAdminCredential inserts a new admin credential.
func (s *Store) CreateAdminCredential(ctx context.Context, c *AdminCredential) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_credentials (id, name, cred_hash, note, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.CredHash, c.Note, nanos(c.CreatedAt),
	)
	if isUniqueViolation(err) {
		return ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("insert admin credential: %w", err)
	}
	return nil
}

// GetAdminCredentialByHash looks up an admin credential by its hash. Returns
// ErrNotFound if absent.
func (s *Store) GetAdminCredentialByHash(ctx context.Context, hash string) (*AdminCredential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+adminColumns+` FROM admin_credentials WHERE cred_hash = ?`, hash)
	return scanAdminCredential(row)
}

// CountAdminCredentials returns the total number of admin credentials.
func (s *Store) CountAdminCredentials(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_credentials`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count admin credentials: %w", err)
	}
	return n, nil
}

// TouchAdminLastUsed updates last_used_at for an admin credential.
func (s *Store) TouchAdminLastUsed(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE admin_credentials SET last_used_at = ? WHERE id = ?`, nanos(at), id)
	return err
}

func scanAdminCredential(sc scanner) (*AdminCredential, error) {
	var (
		c          AdminCredential
		createdAt  int64
		lastUsedAt sql.NullInt64
	)
	err := sc.Scan(&c.ID, &c.Name, &c.CredHash, &c.Note, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan admin credential: %w", err)
	}
	c.CreatedAt = timeFromNanos(createdAt)
	c.LastUsedAt = timeFromNullNanos(lastUsedAt)
	return &c, nil
}

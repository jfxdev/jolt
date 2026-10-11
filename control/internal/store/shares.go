package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Share is a public, read-only link to one path on one node. The token itself
// is never stored: only its digest, so a leaked database cannot be turned into
// working links.
type Share struct {
	ID            string     `json:"share_id"`
	TokenHash     string     `json:"-"`
	NodeID        string     `json:"node_id"`
	MountID       string     `json:"mount_id"`
	Path          string     `json:"path"`
	Kind          string     `json:"kind"`
	Name          string     `json:"name"`
	PasswordHash  string     `json:"-"`
	HasPassword   bool       `json:"has_password"`
	AllowArchive  bool       `json:"allow_archive"`
	MaxDownloads  int64      `json:"max_downloads"`
	DownloadCount int64      `json:"download_count"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	LastAccessAt  *time.Time `json:"last_access_at,omitempty"`
}

// Active reports whether a share may still serve content.
func (s Share) Active(now time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	if s.ExpiresAt != nil && now.After(*s.ExpiresAt) {
		return false
	}
	if s.MaxDownloads > 0 && s.DownloadCount >= s.MaxDownloads {
		return false
	}
	return true
}

const shareColumns = `id,token_hash,node_id,mount_id,path,kind,name,password_hash,allow_archive,
 max_downloads,download_count,created_by,created_at,expires_at,revoked_at,last_access_at`

func (s *Store) CreateShare(ctx context.Context, share Share) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO shares (`+shareColumns+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		share.ID, share.TokenHash, share.NodeID, share.MountID, share.Path, share.Kind, share.Name,
		share.PasswordHash, boolToInt(share.AllowArchive), share.MaxDownloads, share.DownloadCount,
		share.CreatedBy, share.CreatedAt.Format(time.RFC3339Nano),
		nullableTime(share.ExpiresAt), nullableTime(share.RevokedAt), nullableTime(share.LastAccessAt))
	return err
}

// ShareByTokenHash resolves a public token. Lookup is by digest so the token
// never has to be stored or logged.
func (s *Store) ShareByTokenHash(ctx context.Context, tokenHash string) (Share, error) {
	share, err := scanShare(s.db.QueryRowContext(ctx,
		`SELECT `+shareColumns+` FROM shares WHERE token_hash=?`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrNotFound
	}
	return share, err
}

func (s *Store) GetShare(ctx context.Context, id string) (Share, error) {
	share, err := scanShare(s.db.QueryRowContext(ctx,
		`SELECT `+shareColumns+` FROM shares WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrNotFound
	}
	return share, err
}

// ListShares returns shares newest first. A non-empty createdBy restricts the
// listing to one owner, which is how a non-administrator sees only their own.
func (s *Store) ListShares(ctx context.Context, createdBy string) ([]Share, error) {
	query := `SELECT ` + shareColumns + ` FROM shares`
	arguments := []any{}
	if createdBy != "" {
		query += ` WHERE created_by=?`
		arguments = append(arguments, createdBy)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	shares := make([]Share, 0)
	for rows.Next() {
		share, scanErr := scanShare(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		shares = append(shares, share)
	}
	return shares, rows.Err()
}

func (s *Store) RevokeShare(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE shares SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		now.Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteShare(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE id=?`, id)
	return err
}

// RegisterShareDownload counts one download and refuses to exceed the
// configured maximum. The check and the increment share one statement so two
// concurrent downloads cannot both pass a limit of one.
func (s *Store) RegisterShareDownload(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE shares
SET download_count=download_count+1,last_access_at=?
WHERE id=? AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > ?)
  AND (max_downloads<=0 OR download_count < max_downloads)`,
		now.Format(time.RFC3339Nano), id, now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrShareExhausted
	}
	return nil
}

// TouchShare records a read that does not consume the download budget, such as
// opening the landing page or listing a shared directory.
func (s *Store) TouchShare(ctx context.Context, id string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE shares SET last_access_at=? WHERE id=?`,
		now.Format(time.RFC3339Nano), id)
	return err
}

// PurgeExpiredShares removes shares that expired before the cutoff so the table
// does not grow without bound.
func (s *Store) PurgeExpiredShares(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM shares WHERE expires_at IS NOT NULL AND expires_at < ?`,
		before.Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ErrShareExhausted reports that a share is revoked, expired, or has no
// downloads left.
var ErrShareExhausted = errors.New("share is no longer available")

func scanShare(row scanner) (Share, error) {
	var share Share
	var allowArchive int
	var created string
	var expires, revoked, lastAccess sql.NullString
	err := row.Scan(&share.ID, &share.TokenHash, &share.NodeID, &share.MountID, &share.Path,
		&share.Kind, &share.Name, &share.PasswordHash, &allowArchive, &share.MaxDownloads,
		&share.DownloadCount, &share.CreatedBy, &created, &expires, &revoked, &lastAccess)
	if err != nil {
		return share, err
	}
	share.AllowArchive = allowArchive != 0
	share.HasPassword = share.PasswordHash != ""
	share.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	share.ExpiresAt = parseNullableTime(expires)
	share.RevokedAt = parseNullableTime(revoked)
	share.LastAccessAt = parseNullableTime(lastAccess)
	return share, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

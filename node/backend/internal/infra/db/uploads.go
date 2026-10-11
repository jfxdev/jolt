package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// ErrUploadSessionExists reports that another unfinished upload already targets
// the same destination. Two concurrent resumable uploads to one path would
// interleave into the same partial file and publish corrupted content, so the
// second one is refused instead.
var ErrUploadSessionExists = errors.New("an upload session already targets this destination")

const uploadSessionColumns = `id,mount_id,destination,size,overwrite,checksum,chunk_size,correlation_id,created_at,updated_at,expires_at`

func (s *Store) CreateUploadSession(ctx context.Context, session entities.UploadSession) error {
	overwrite := 0
	if session.Overwrite {
		overwrite = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO upload_sessions (`+uploadSessionColumns+`)
VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		session.ID, session.MountID, session.Destination, session.Size, overwrite,
		session.Checksum, session.ChunkSize, session.CorrelationID,
		session.CreatedAt.Format(time.RFC3339Nano), session.UpdatedAt.Format(time.RFC3339Nano),
		session.ExpiresAt.Format(time.RFC3339Nano))
	if err != nil && isUniqueViolation(err) {
		return ErrUploadSessionExists
	}
	return err
}

func (s *Store) GetUploadSession(ctx context.Context, id string) (entities.UploadSession, error) {
	session, err := scanUploadSession(s.db.QueryRowContext(ctx,
		`SELECT `+uploadSessionColumns+` FROM upload_sessions WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return entities.UploadSession{}, ErrNotFound
	}
	return session, err
}

// ListUploadSessions returns the unfinished uploads for a mount, newest first,
// so the UI can offer to resume them after a reload or a browser restart.
func (s *Store) ListUploadSessions(ctx context.Context, mountID string) ([]entities.UploadSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+uploadSessionColumns+`
FROM upload_sessions WHERE mount_id=? ORDER BY created_at DESC`, mountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]entities.UploadSession, 0)
	for rows.Next() {
		session, scanErr := scanUploadSession(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// TouchUploadSession extends the expiry while bytes keep arriving, so a slow
// but live upload is not swept out from under the client.
func (s *Store) TouchUploadSession(ctx context.Context, id string, now, expiresAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE upload_sessions SET updated_at=?,expires_at=? WHERE id=?`,
		now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano), id)
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

func (s *Store) DeleteUploadSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM upload_sessions WHERE id=?`, id)
	return err
}

// ExpiredUploadSessions returns sessions past their expiry so the caller can
// remove their partial files before deleting the rows.
func (s *Store) ExpiredUploadSessions(ctx context.Context, before time.Time) ([]entities.UploadSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+uploadSessionColumns+`
FROM upload_sessions WHERE expires_at < ?`, before.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]entities.UploadSession, 0)
	for rows.Next() {
		session, scanErr := scanUploadSession(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func scanUploadSession(row scanner) (entities.UploadSession, error) {
	var session entities.UploadSession
	var overwrite int
	var created, updated, expires string
	err := row.Scan(&session.ID, &session.MountID, &session.Destination, &session.Size,
		&overwrite, &session.Checksum, &session.ChunkSize, &session.CorrelationID,
		&created, &updated, &expires)
	if err != nil {
		return session, err
	}
	session.Overwrite = overwrite != 0
	session.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	session.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	session.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	return session, nil
}

// isUniqueViolation detects a UNIQUE constraint failure. The SQLCipher driver
// wraps the SQLite error without exposing a typed code, so the message is the
// only signal available.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}

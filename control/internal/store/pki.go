package store

import (
	"context"
	"database/sql"
	"time"
)

// PKI object kinds. The store keeps them opaque; internal/pki decides what a
// secret or a public part means.
const (
	PKIRoot         = "root"
	PKIIntermediate = "intermediate"
	PKISigningKey   = "signing_key"
	PKIBundle       = "bundle"
)

// PKIObject is one certificate, key or bundle the Control Tower's own
// certificate authority keeps. Secret is already encrypted by the caller.
type PKIObject struct {
	ID          string
	Kind        string
	State       string
	Serial      string
	Fingerprint string
	Public      string
	Secret      string
	NotBefore   time.Time
	NotAfter    time.Time
	CreatedAt   time.Time
}

// ListPKIObjects returns every object, oldest first.
func (s *Store) ListPKIObjects(ctx context.Context) ([]PKIObject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,state,serial,fingerprint,public,secret,not_before,not_after,created_at FROM pki_objects ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var objects []PKIObject
	for rows.Next() {
		var object PKIObject
		var notBefore, notAfter, createdAt string
		if err := rows.Scan(&object.ID, &object.Kind, &object.State, &object.Serial, &object.Fingerprint, &object.Public, &object.Secret, &notBefore, &notAfter, &createdAt); err != nil {
			return nil, err
		}
		object.NotBefore, _ = time.Parse(time.RFC3339Nano, notBefore)
		object.NotAfter, _ = time.Parse(time.RFC3339Nano, notAfter)
		object.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		objects = append(objects, object)
	}
	return objects, rows.Err()
}

// SavePKIObjects writes and removes objects in one transaction. The first
// write raises the database's minimum security version: an older binary would
// neither know these tables nor keep a rotation consistent.
func (s *Store) SavePKIObjects(ctx context.Context, put []PKIObject, remove []string) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','9') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<9 THEN '9' ELSE value END`); err != nil {
		return err
	}
	for _, id := range remove {
		if _, err := tx.ExecContext(ctx, `DELETE FROM pki_objects WHERE id=?`, id); err != nil {
			return err
		}
	}
	for _, object := range put {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pki_objects(id,kind,state,serial,fingerprint,public,secret,not_before,not_after,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET state=excluded.state, public=excluded.public, secret=excluded.secret, not_after=excluded.not_after`,
			object.ID, object.Kind, object.State, object.Serial, object.Fingerprint, object.Public, object.Secret,
			object.NotBefore.UTC().Format(time.RFC3339Nano), object.NotAfter.UTC().Format(time.RFC3339Nano), object.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

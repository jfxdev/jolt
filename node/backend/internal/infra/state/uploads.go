package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func (s *Store) CreateUploadSession(ctx context.Context, v entities.UploadSession) error {
	if v.AuthorizationRevision != 0 {
		return errors.New("invalid initial upload authorization revision")
	}
	if v.AuthorizationActorID != "" || v.AuthorizationCredentialID != "" {
		if !signedauth.ValidKeyID(v.AuthorizationActorID) || !signedauth.ValidKeyID(v.AuthorizationCredentialID) {
			return errors.New("invalid upload authorization identity")
		}
	}
	return s.update(ctx, func(tx *transaction) error {
		if _, exists := s.index["uploads"][v.ID]; exists {
			return ErrUploadSessionExists
		}
		for _, key := range keys(s, "uploads", v.MountID) {
			other, err := get[entities.UploadSession](s, "uploads", key)
			if err != nil {
				return err
			}
			if other.Destination == v.Destination && other.State != "completed" {
				return ErrUploadSessionExists
			}
		}
		if v.AuthorizationActorID != "" {
			if err := s.ensureUploadSecurityVersion(2); err != nil {
				return err
			}
		}
		return tx.put("uploads", v.ID, v.MountID, order(v.CreatedAt), v)
	})
}

// Called under the state lock, before any record requiring the new contract.
func (s *Store) ensureUploadSecurityVersion(required int) error {
	if s.envelopeVersion >= required {
		return nil
	}
	s.envelopeVersion = required
	if _, err := s.write("store.yaml", "header", 0, struct {
		Format string `yaml:"format"`
	}{"jolt-yaml-state"}); err != nil {
		s.poison()
		return fmt.Errorf("%w: security version: %v", contracts.ErrStateUnavailable, err)
	}
	return nil
}

// ReauthorizeUploadSession atomically binds a legacy session or replaces a
// credential for the same actor. Callers must verify current authorization
// and hold the session operation lock before invoking it.
func (s *Store) ReauthorizeUploadSession(ctx context.Context, id, actorID, credentialID, expectedRequestID string) error {
	if !signedauth.ValidKeyID(actorID) || !signedauth.ValidKeyID(credentialID) {
		return errors.New("invalid upload authorization identity")
	}
	return s.update(ctx, func(tx *transaction) error {
		session, err := get[entities.UploadSession](s, "uploads", id)
		if err != nil {
			return err
		}
		if (session.AuthorizationActorID == "") != (session.AuthorizationCredentialID == "") || session.AuthorizationActorID != "" && session.AuthorizationActorID != actorID || session.AuthorizationRevision == ^uint64(0) || signedauth.UploadReauthorizationRequestID(id, session.AuthorizationCredentialID, session.AuthorizationRevision) != expectedRequestID {
			return ErrInUse
		}
		if err := s.ensureUploadSecurityVersion(3); err != nil {
			return err
		}
		session.AuthorizationActorID, session.AuthorizationCredentialID = actorID, credentialID
		session.AuthorizationRevision++
		return tx.put("uploads", id, session.MountID, order(session.CreatedAt), session)
	})
}
func (s *Store) GetUploadSession(ctx context.Context, id string) (v entities.UploadSession, err error) {
	err = s.view(ctx, func() error { v, err = get[entities.UploadSession](s, "uploads", id); return err })
	return
}
func (s *Store) ListUploadSessions(ctx context.Context, mount string) (out []entities.UploadSession, err error) {
	out = []entities.UploadSession{}
	err = s.view(ctx, func() error {
		ids := keys(s, "uploads", mount)
		for i := len(ids) - 1; i >= 0; i-- {
			v, e := get[entities.UploadSession](s, "uploads", ids[i])
			if e != nil {
				return e
			}
			if v.State != "completed" {
				out = append(out, v)
			}
		}
		return nil
	})
	return
}
func (s *Store) TouchUploadSession(ctx context.Context, id string, now, expires time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		v, e := get[entities.UploadSession](s, "uploads", id)
		if e != nil {
			return e
		}
		v.UpdatedAt, v.ExpiresAt = now, expires
		return tx.put("uploads", id, v.MountID, order(v.CreatedAt), v)
	})
}
func (s *Store) DeleteUploadSession(ctx context.Context, id string) error {
	return s.update(ctx, func(tx *transaction) error { tx.remove("uploads", id); return nil })
}
func (s *Store) ExpiredUploadSessions(ctx context.Context, before time.Time) (out []entities.UploadSession, err error) {
	err = s.view(ctx, func() error {
		for _, id := range keys(s, "uploads", "") {
			v, e := get[entities.UploadSession](s, "uploads", id)
			if e != nil {
				return e
			}
			if v.ExpiresAt.Before(before) {
				out = append(out, v)
			}
		}
		return nil
	})
	return
}

func (s *Store) UpdateUploadSession(ctx context.Context, v entities.UploadSession) error {
	return s.update(ctx, func(tx *transaction) error {
		old, err := get[entities.UploadSession](s, "uploads", v.ID)
		if err != nil {
			return err
		}
		if old.MountID != v.MountID || old.Destination != v.Destination || old.Size != v.Size || old.Overwrite != v.Overwrite || old.AuthorizationActorID != v.AuthorizationActorID || old.AuthorizationCredentialID != v.AuthorizationCredentialID || old.AuthorizationRevision != v.AuthorizationRevision {
			return ErrInUse
		}
		return tx.put("uploads", v.ID, v.MountID, order(v.CreatedAt), v)
	})
}

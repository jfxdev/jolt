package state

import (
	"context"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"time"
)

func (s *Store) CreateUploadSession(ctx context.Context, v entities.UploadSession) error {
	return s.update(ctx, func(tx *transaction) error {
		if _, exists := s.index["uploads"][v.ID]; exists {
			return ErrUploadSessionExists
		}
		for _, key := range keys(s, "uploads", v.MountID) {
			other, err := get[entities.UploadSession](s, "uploads", key)
			if err != nil {
				return err
			}
			if other.Destination == v.Destination {
				return ErrUploadSessionExists
			}
		}
		return tx.put("uploads", v.ID, v.MountID, order(v.CreatedAt), v)
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
			out = append(out, v)
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

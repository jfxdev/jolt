package state

import (
	"context"
	"errors"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"time"
)

func (s *Store) GetOperationalTokenState(ctx context.Context) (v entities.OperationalTokenState, err error) {
	err = s.view(ctx, func() error { v, err = get[entities.OperationalTokenState](s, "tokens", "operational"); return err })
	return
}
func (s *Store) StageOperationalToken(ctx context.Context, hash, correlation string, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		v, e := get[entities.OperationalTokenState](s, "tokens", "operational")
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		v.StagedHash, v.UpdatedAt, v.CorrelationID = hash, now, correlation
		return tx.put("tokens", "operational", "", "", v)
	})
}
func (s *Store) CommitOperationalToken(ctx context.Context, hash, correlation string, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		v, e := get[entities.OperationalTokenState](s, "tokens", "operational")
		if e != nil {
			return e
		}
		if hash == "" || v.StagedHash != hash {
			return ErrNotFound
		}
		v.ActiveHash, v.StagedHash, v.EnvTokenDisabled, v.UpdatedAt, v.CorrelationID = hash, "", true, now, correlation
		return tx.put("tokens", "operational", "", "", v)
	})
}
func (s *Store) RecoverOperationalToken(ctx context.Context, hash, correlation string, now time.Time) error {
	if hash == "" || correlation == "" {
		return errors.New("token hash and correlation ID are required")
	}
	return s.update(ctx, func(tx *transaction) error {
		return tx.put("tokens", "operational", "", "", entities.OperationalTokenState{ActiveHash: hash, EnvTokenDisabled: true, UpdatedAt: now, CorrelationID: correlation})
	})
}

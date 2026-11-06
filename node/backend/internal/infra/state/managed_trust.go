package state

import (
	"context"
	"errors"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// GetManagedTrust returns the enrollment state, or ErrNotFound for a node that
// is configured by hand.
func (s *Store) GetManagedTrust(ctx context.Context) (value entities.ManagedTrust, err error) {
	err = s.view(ctx, func() error {
		value, err = get[entities.ManagedTrust](s, "managed_trust", "current")
		return err
	})
	return value, err
}

// PutManagedTrust replaces the enrollment state. The first write raises the
// state security version, so a node that does not know managed trust cannot
// open a state whose API certificate and trusted keys it would ignore.
func (s *Store) PutManagedTrust(ctx context.Context, value entities.ManagedTrust) error {
	if value.RootPin == "" || value.Bundle == "" {
		return errors.New("managed trust needs a pinned root and a bundle")
	}
	return s.update(ctx, func(tx *transaction) error {
		if err := s.ensureSecurityVersion(8); err != nil {
			return err
		}
		return tx.put("managed_trust", "current", "", "", value)
	})
}

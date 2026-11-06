package state

import (
	"context"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

func validTrashItem(item entities.TrashItem) bool {
	return signedauth.ValidKeyID(item.ID) && signedauth.ValidKeyID(item.MountID) && planPath(item.Path) && utf8.ValidString(item.Path) &&
		(item.Type == "file" || item.Type == "directory") && item.Size >= 0 && !item.DeletedAt.IsZero() && item.ExpiresAt.After(item.DeletedAt) &&
		(item.State == "moving" || item.State == "stored" || item.State == "purging") &&
		item.Path != ".jolt-trash" && !strings.HasPrefix(item.Path, ".jolt-trash/")
}

// PutTrashItem writes or replaces a record. The first record raises the state
// security version, so a node that does not know the trash cannot open the
// state and forget what a mount keeps.
func (s *Store) PutTrashItem(ctx context.Context, item entities.TrashItem) error {
	if !validTrashItem(item) {
		return errors.New("invalid trash item")
	}
	return s.update(ctx, func(tx *transaction) error {
		if err := s.ensureSecurityVersion(7); err != nil {
			return err
		}
		return tx.put("trash", item.ID, item.MountID, order(item.DeletedAt), item)
	})
}

func (s *Store) GetTrashItem(ctx context.Context, id string) (item entities.TrashItem, err error) {
	if !signedauth.ValidKeyID(id) {
		return item, ErrNotFound
	}
	err = s.view(ctx, func() error {
		item, err = get[entities.TrashItem](s, "trash", id)
		return err
	})
	return item, err
}

// ListTrashItems returns a mount's records, newest first.
func (s *Store) ListTrashItems(ctx context.Context, mountID string) (items []entities.TrashItem, err error) {
	err = s.view(ctx, func() error {
		for _, id := range keys(s, "trash", mountID) {
			item, err := get[entities.TrashItem](s, "trash", id)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return nil
	})
	sort.SliceStable(items, func(a, b int) bool { return items[a].DeletedAt.After(items[b].DeletedAt) })
	return items, err
}

func (s *Store) AllTrashItems(ctx context.Context) (items []entities.TrashItem, err error) {
	err = s.view(ctx, func() error {
		for _, id := range keys(s, "trash", "") {
			item, err := get[entities.TrashItem](s, "trash", id)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		return nil
	})
	return items, err
}

func (s *Store) DeleteTrashItem(ctx context.Context, id string) error {
	if !signedauth.ValidKeyID(id) {
		return ErrNotFound
	}
	return s.update(ctx, func(tx *transaction) error {
		if _, exists := s.index["trash"][id]; !exists {
			return ErrNotFound
		}
		tx.remove("trash", id)
		return nil
	})
}

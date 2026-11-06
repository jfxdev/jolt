package filesystem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
)

// A mount with trash enabled does not delete: it renames the entry, in one
// atomic step on the same filesystem, to <mount>/.jolt-trash/<id>/<path>. The
// folder is internal, so no listing, search, archive or direct request reaches
// it. A record in the encrypted state is written before the rename and removed
// after the entry is gone, which lets a restart finish or undo either step.

const trashFolder = ".jolt-trash"

var (
	ErrTrashUnavailable = errors.New("trash cannot hold this entry")
	ErrTrashNotFound    = errors.New("trash entry not found")
	ErrTrashFull        = errors.New("the trash is full")
)

// trashMu serializes every change to the trash. Deletes, restores and purges
// are rare next to reads, and one lock keeps each record and its folder in step.
var trashMu sync.Mutex

func trashEnabled(mount entities.Mount) bool {
	return mount.Trash != nil && mount.Trash.Enabled && mount.Mode == "read_write"
}

func trashRetention(mount entities.Mount) time.Duration {
	days := 30
	if mount.Trash != nil && mount.Trash.RetentionDays > 0 {
		days = mount.Trash.RetentionDays
	}
	return time.Duration(days) * 24 * time.Hour
}

func newTrashID(now time.Time) string {
	random := make([]byte, 6)
	_, _ = rand.Read(random)
	return fmt.Sprintf("tr_%d_%s", now.Unix(), hex.EncodeToString(random))
}

// trashRoot returns the trash folder of a mount, creating it when asked. It
// refuses anything that is not a plain directory, so a link planted there on
// the host cannot redirect a delete outside the mount.
func trashRoot(mount entities.Mount, create bool) (string, error) {
	root := filepath.Join(mount.LocalPath, trashFolder)
	info, err := safeLstat(root)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		info, err = safeLstat(root)
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: the trash folder is not a plain directory", ErrTrashUnavailable)
	}
	return root, nil
}

func trashPayload(root, id, relative string) string {
	return filepath.Join(root, id, filepath.FromSlash(relative))
}

// moveToTrash replaces a permanent delete. info describes resolved, which the
// caller has already validated; relative is its clean mount-relative path.
func (s *Service) moveToTrash(ctx context.Context, mount entities.Mount, relative, resolved string, info os.FileInfo) error {
	slashed := filepath.ToSlash(relative)
	if slashed == trashFolder || strings.HasPrefix(slashed, trashFolder+"/") {
		return ErrNotFound
	}
	trashMu.Lock()
	defer trashMu.Unlock()
	root, err := trashRoot(mount, true)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	item := entities.TrashItem{
		ID: newTrashID(now), MountID: mount.ID, Path: slashed, Type: "file", State: "moving",
		DeletedAt: now, ExpiresAt: now.Add(trashRetention(mount)),
	}
	if info.IsDir() {
		item.Type = "directory"
		if item.Size, err = treeBytes(ctx, resolved); err != nil {
			return err
		}
	} else {
		item.Size = info.Size()
	}
	if limit := mount.Trash.MaxBytes; limit > 0 {
		held, err := s.store.ListTrashItems(ctx, mount.ID)
		if err != nil {
			return err
		}
		total := item.Size
		for _, other := range held {
			total += other.Size
		}
		if total > limit {
			return fmt.Errorf("%w: it would hold %d bytes of the %d allowed; purge something first", ErrTrashFull, total, limit)
		}
	}
	if err := s.store.PutTrashItem(ctx, item); err != nil {
		return err
	}
	payload := trashPayload(root, item.ID, slashed)
	moved := false
	defer func() {
		// Nothing moved: forget the intent and any folder made for it.
		if !moved {
			_ = os.RemoveAll(filepath.Join(root, item.ID))
			_ = s.store.DeleteTrashItem(context.WithoutCancel(ctx), item.ID)
		}
	}()
	if err := os.MkdirAll(filepath.Dir(payload), 0o700); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publishPath(resolved, payload, false); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			return fmt.Errorf("%w: the entry is on another filesystem than the mount", ErrTrashUnavailable)
		}
		return err
	}
	moved = true
	item.State = "stored"
	if err := s.store.PutTrashItem(context.WithoutCancel(ctx), item); err != nil {
		// The entry is safely in the trash; recovery marks it stored.
		return fmt.Errorf("record trash entry: %w", err)
	}
	return nil
}

// ListTrash returns the entries a mount keeps, newest first.
func (s *Service) ListTrash(ctx context.Context, mountID string) ([]entities.TrashItem, error) {
	if _, err := s.GetMount(ctx, mountID); err != nil {
		return nil, err
	}
	items, err := s.store.ListTrashItems(ctx, mountID)
	if err != nil {
		return nil, err
	}
	stored := items[:0]
	for _, item := range items {
		if item.State == "stored" {
			stored = append(stored, item)
		}
	}
	return stored, nil
}

func (s *Service) trashItem(ctx context.Context, mountID, id string) (entities.TrashItem, error) {
	item, err := s.store.GetTrashItem(ctx, id)
	if errors.Is(err, contracts.ErrNotFound) || err == nil && (item.MountID != mountID || item.State != "stored") {
		return entities.TrashItem{}, ErrTrashNotFound
	}
	return item, err
}

// GetTrash returns one stored entry of a mount.
func (s *Service) GetTrash(ctx context.Context, mountID, id string) (entities.TrashItem, error) {
	if _, err := s.GetMount(ctx, mountID); err != nil {
		return entities.TrashItem{}, err
	}
	return s.trashItem(ctx, mountID, id)
}

// RestoreTrash puts an entry back where it was. It checks the destination
// again, as for any new file: the mount must be writable, the path safe and
// not hidden, the parent present and nothing already there.
func (s *Service) RestoreTrash(ctx context.Context, mountID, id string) (entities.TrashItem, error) {
	trashMu.Lock()
	defer trashMu.Unlock()
	item, err := s.trashItem(ctx, mountID, id)
	if err != nil {
		return item, err
	}
	mount, destination, err := s.resolve(ctx, mountID, item.Path, true)
	if err != nil {
		return item, err
	}
	if err := writable(mount); err != nil {
		return item, err
	}
	root, err := trashRoot(mount, false)
	if err != nil {
		return item, err
	}
	payload := trashPayload(root, item.ID, item.Path)
	if _, err := safeLstat(payload); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The record outlived the entry: nothing to restore.
			_ = s.store.DeleteTrashItem(ctx, item.ID)
			return item, ErrTrashNotFound
		}
		return item, err
	}
	if _, err := safeLstat(destination); err == nil {
		return item, ErrConflict
	} else if !errors.Is(err, fs.ErrNotExist) {
		return item, err
	}
	if err := ctx.Err(); err != nil {
		return item, err
	}
	if err := publishPath(payload, destination, false); err != nil {
		return item, err
	}
	// The entry is back. What is left is empty folders and a record.
	_ = os.RemoveAll(filepath.Join(root, item.ID))
	return item, s.store.DeleteTrashItem(context.WithoutCancel(ctx), item.ID)
}

// PurgeTrash deletes an entry for good.
func (s *Service) PurgeTrash(ctx context.Context, mountID, id string) (entities.TrashItem, error) {
	trashMu.Lock()
	defer trashMu.Unlock()
	item, err := s.trashItem(ctx, mountID, id)
	if err != nil {
		return item, err
	}
	return item, s.purge(ctx, item)
}

// purge records the intent before removing anything, so a restart finishes it.
func (s *Service) purge(ctx context.Context, item entities.TrashItem) error {
	mount, err := s.GetMount(ctx, item.MountID)
	if err != nil {
		return err
	}
	if item.State != "purging" {
		item.State = "purging"
		if err := s.store.PutTrashItem(ctx, item); err != nil {
			return err
		}
	}
	root, err := trashRoot(mount, false)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := os.RemoveAll(filepath.Join(root, item.ID)); err != nil {
			return err
		}
	}
	return s.store.DeleteTrashItem(context.WithoutCancel(ctx), item.ID)
}

// SweepTrash purges what has passed its retention. It reports how many it
// removed and keeps going past a mount that cannot be reached.
func (s *Service) SweepTrash(ctx context.Context, now time.Time) (int, error) {
	trashMu.Lock()
	defer trashMu.Unlock()
	items, err := s.store.AllTrashItems(ctx)
	if err != nil {
		return 0, err
	}
	purged := 0
	var failure error
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return purged, err
		}
		if item.State != "stored" || now.Before(item.ExpiresAt) {
			continue
		}
		if err := s.purge(ctx, item); err != nil {
			failure = errors.Join(failure, fmt.Errorf("purge %s: %w", item.ID, err))
			continue
		}
		purged++
	}
	return purged, failure
}

// RecoverTrash reconciles records with folders after a restart, when nothing
// can be in the middle of a change. A record left "moving" is kept if the
// entry reached the trash and dropped if it did not; "purging" is finished;
// a "stored" record whose entry is gone is dropped.
func (s *Service) RecoverTrash(ctx context.Context) (int, error) {
	trashMu.Lock()
	defer trashMu.Unlock()
	items, err := s.store.AllTrashItems(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	var failure error
	for _, item := range items {
		mount, err := s.GetMount(ctx, item.MountID)
		if err != nil {
			// A mount that is gone or unreachable keeps its records until it returns.
			continue
		}
		// A mount that cannot be read right now (an unmounted disk) tells us
		// nothing about what its trash holds: leave the records alone.
		if !mount.Readable || !mount.Enabled {
			continue
		}
		root, rootErr := trashRoot(mount, false)
		if rootErr != nil && !errors.Is(rootErr, fs.ErrNotExist) {
			failure = errors.Join(failure, fmt.Errorf("recover %s: %w", item.ID, rootErr))
			continue
		}
		present := false
		if rootErr == nil {
			_, statErr := safeLstat(trashPayload(root, item.ID, item.Path))
			present = statErr == nil
		}
		switch {
		case item.State == "purging":
			err = s.purge(ctx, item)
		case present && item.State == "moving":
			item.State = "stored"
			err = s.store.PutTrashItem(ctx, item)
		case present:
			continue
		default:
			// The entry is not in the trash: either the move never happened or
			// the folder was removed on the host. There is nothing to keep.
			if rootErr == nil {
				_ = os.RemoveAll(filepath.Join(root, item.ID))
			}
			err = s.store.DeleteTrashItem(ctx, item.ID)
		}
		if err != nil {
			failure = errors.Join(failure, fmt.Errorf("recover %s: %w", item.ID, err))
			continue
		}
		changed++
	}
	return changed, failure
}

// treeBytes adds up the regular files under root. It follows no link.
func treeBytes(ctx context.Context, root string) (int64, error) {
	var total int64
	err := safeWalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// TrashStats is what a mount's trash holds right now.
type TrashStats struct {
	MountID string
	Entries int
	Bytes   int64
	Oldest  time.Time
}

// TrashStats summarizes the stored entries per mount, for metrics.
func (s *Service) TrashStats(ctx context.Context) ([]TrashStats, error) {
	items, err := s.store.AllTrashItems(ctx)
	if err != nil {
		return nil, err
	}
	byMount := map[string]*TrashStats{}
	var order []string
	for _, item := range items {
		if item.State != "stored" {
			continue
		}
		stats := byMount[item.MountID]
		if stats == nil {
			stats = &TrashStats{MountID: item.MountID}
			byMount[item.MountID] = stats
			order = append(order, item.MountID)
		}
		stats.Entries++
		stats.Bytes += item.Size
		if stats.Oldest.IsZero() || item.DeletedAt.Before(stats.Oldest) {
			stats.Oldest = item.DeletedAt
		}
	}
	result := make([]TrashStats, 0, len(order))
	for _, id := range order {
		result = append(result, *byMount[id])
	}
	return result, nil
}

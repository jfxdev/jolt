package state

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"time"
)

type configurationRecord struct {
	Revision  string    `yaml:"revision"`
	AppliedAt time.Time `yaml:"applied_at"`
	Settings  string    `yaml:"settings,omitempty"`
}
type auditRecord struct {
	Action     string    `yaml:"action"`
	ResourceID string    `yaml:"resource_id"`
	At         time.Time `yaml:"at"`
	Snapshot   any       `yaml:"snapshot"`
}

func (tx *transaction) audit(action, id string, value any) error {
	key := fmt.Sprintf("%020d-%06d", tx.store.sequence+1, len(tx.records))
	return tx.put("audit", key, id, key, auditRecord{action, id, time.Now().UTC(), value})
}

// ApplyConfiguration applies the complete desired resource set atomically. Bindings
// and revocation tombstones survive deletion from the operator's file.
func (s *Store) ApplyConfiguration(ctx context.Context, revision string, mounts []entities.Mount, grants []entities.TransferPathGrant, settings ...string) error {
	publicSettings := ""
	if len(settings) > 0 {
		publicSettings = settings[0]
	}
	err := s.update(ctx, func(tx *transaction) error {
		old, e := get[configurationRecord](s, "configuration", "applied")
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if old.Revision == revision {
			return nil
		}
		for _, id := range keys(s, "mounts", "") {
			tx.remove("mounts", id)
		}
		for _, id := range keys(s, "grants", "") {
			tx.remove("grants", id)
		}
		now := time.Now().UTC()
		for _, m := range mounts {
			binding, e := get[string](s, "mount_bindings", m.ID)
			if e == nil && binding != m.LocalPath {
				return fmt.Errorf("mount %s changed root: use a new ID", m.ID)
			}
			if e != nil && !errors.Is(e, ErrNotFound) {
				return e
			}
			existing, e := get[entities.Mount](s, "mounts", m.ID)
			if e == nil {
				m.CreatedAt = existing.CreatedAt
			}
			if m.CreatedAt.IsZero() {
				m.CreatedAt = now
			}
			m.UpdatedAt = now
			if e = tx.put("mount_bindings", m.ID, "", "", m.LocalPath); e != nil {
				return e
			}
			if e = tx.put("mounts", m.ID, "", m.Name, m); e != nil {
				return e
			}
		}
		for _, g := range grants {
			binding := g.PeerNodeID + "\x00" + g.MountID + "\x00" + g.Path + "\x00" + g.Direction
			previous, e := get[string](s, "grant_bindings", g.ID)
			if e == nil && binding != previous {
				return fmt.Errorf("grant %s changed resource: use a new ID", g.ID)
			}
			if e != nil && !errors.Is(e, ErrNotFound) {
				return e
			}
			if errors.Is(e, ErrNotFound) {
				peer, peerErr := get[entities.Peer](s, "peers", g.PeerNodeID)
				if peerErr != nil && !errors.Is(peerErr, ErrNotFound) {
					return peerErr
				}
				// Reauthorization of a revoked relationship requires both renewed
				// trust and a subsequently declared new grant identity.
				if peerErr == nil && peer.State == "revoked" {
					if err := tx.put("revoked_grants", g.ID, g.PeerNodeID, "", true); err != nil {
						return err
					}
				}
			}
			existing, e := get[entities.TransferPathGrant](s, "grants", g.ID)
			if e == nil {
				g.CreatedAt = existing.CreatedAt
			}
			if g.CreatedAt.IsZero() {
				g.CreatedAt = now
			}
			g.UpdatedAt = now
			if e = tx.put("grant_bindings", g.ID, "", "", binding); e != nil {
				return e
			}
			if e = tx.put("grants", g.ID, g.PeerNodeID, order(g.CreatedAt), g); e != nil {
				return e
			}
		}
		// Retain before and after resource sets in encrypted audit history.
		beforeMounts := []entities.Mount{}
		for _, id := range keys(s, "mounts", "") {
			v, e := get[entities.Mount](s, "mounts", id)
			if e != nil {
				return e
			}
			beforeMounts = append(beforeMounts, v)
		}
		beforeGrants := []entities.TransferPathGrant{}
		for _, id := range keys(s, "grants", "") {
			v, e := get[entities.TransferPathGrant](s, "grants", id)
			if e != nil {
				return e
			}
			beforeGrants = append(beforeGrants, v)
		}
		if e = tx.audit("configuration_applied", revision, map[string]any{"previous_revision": old.Revision, "configuration_before": old.Settings, "configuration_after": publicSettings, "mounts_before": beforeMounts, "mounts_after": mounts, "grants_before": beforeGrants, "grants_after": grants}); e != nil {
			return e
		}
		return tx.put("configuration", "applied", "", "", configurationRecord{revision, now, publicSettings})
	})
	if err == nil {
		s.mu.Lock()
		s.managed = true
		s.mu.Unlock()
	}
	return err
}
func (s *Store) GetMount(ctx context.Context, id string) (v entities.Mount, err error) {
	err = s.view(ctx, func() error { v, err = get[entities.Mount](s, "mounts", id); return err })
	return
}
func (s *Store) ListMounts(ctx context.Context) (out []entities.Mount, err error) {
	err = s.view(ctx, func() error {
		for _, id := range keys(s, "mounts", "") {
			v, e := get[entities.Mount](s, "mounts", id)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}

// Programmatic configuration writers support isolated service fixtures. Once a
// configuration has been applied, all mutations are rejected at the adapter too.
func (s *Store) UpsertMount(ctx context.Context, v entities.Mount) error {
	return s.update(ctx, func(tx *transaction) error {
		if s.managed {
			return contracts.ErrManagedConfiguration
		}
		for _, id := range keys(s, "mounts", "") {
			m, e := get[entities.Mount](s, "mounts", id)
			if e != nil {
				return e
			}
			if id != v.ID && m.LocalPath == v.LocalPath {
				return errors.New("mount path already exists")
			}
		}
		return tx.put("mounts", v.ID, "", v.Name, v)
	})
}
func (s *Store) DeleteMount(ctx context.Context, id string) error {
	return s.update(ctx, func(tx *transaction) error {
		if s.managed {
			return contracts.ErrManagedConfiguration
		}
		if _, ok := s.index["mounts"][id]; !ok {
			return ErrNotFound
		}
		for _, key := range keys(s, "grants", "") {
			g, e := get[entities.TransferPathGrant](s, "grants", key)
			if e != nil {
				return e
			}
			if g.MountID == id {
				return ErrInUse
			}
		}
		tx.remove("mounts", id)
		return nil
	})
}
func (s *Store) effectiveGrant(g entities.TransferPathGrant) (entities.TransferPathGrant, error) {
	g.ConfiguredEnabled = g.Enabled
	if !g.Enabled {
		g.InactiveReason = "disabled"
		return g, nil
	}
	if _, blocked := s.index["revoked_grants"][g.ID]; blocked {
		g.Enabled = false
		g.InactiveReason = "revoked"
		return g, nil
	}
	if !s.managed {
		return g, nil
	}
	peer, e := get[entities.Peer](s, "peers", g.PeerNodeID)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return g, e
	}
	if e != nil || !entities.TrustedPeerState(peer.State) {
		g.Enabled = false
		g.InactiveReason = "peer_untrusted"
		return g, nil
	}
	m, e := get[entities.Mount](s, "mounts", g.MountID)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return g, e
	}
	if e != nil || !m.Enabled {
		g.Enabled = false
		g.InactiveReason = "mount_unavailable"
		return g, nil
	}
	if (g.Permissions.Write || g.Permissions.Delete || g.Permissions.Rename || g.Direction != "send") && m.Mode != "read_write" {
		g.Enabled = false
		g.InactiveReason = "mount_read_only"
		return g, nil
	}
	if peer.TransferMode == "one_sided" && ((peer.LocalRole == "sender" && g.Direction != "send") || (peer.LocalRole == "receiver" && g.Direction != "receive")) {
		g.Enabled = false
		g.InactiveReason = "peer_role_incompatible"
		return g, nil
	}
	root, e := filepath.EvalSymlinks(m.LocalPath)
	if e != nil || root != m.LocalPath {
		g.Enabled = false
		g.InactiveReason = "mount_unavailable"
		return g, nil
	}
	target, e := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(g.Path)))
	if e != nil {
		g.Enabled = false
		g.InactiveReason = "path_unavailable"
		return g, nil
	}
	relative, e := filepath.Rel(root, target)
	if e != nil || relative == ".." || !filepath.IsLocal(relative) {
		g.Enabled = false
		g.InactiveReason = "path_unavailable"
		return g, nil
	}
	info, e := os.Stat(target)
	if e != nil {
		g.Enabled = false
		g.InactiveReason = "path_unavailable"
		return g, nil
	}
	var access uint32
	if g.Permissions.Read {
		access |= unix.R_OK
	}
	if g.Permissions.Write || g.Permissions.Rename || g.Permissions.Delete {
		access |= unix.W_OK
	}
	if info.IsDir() {
		access |= unix.X_OK
	}
	if unix.Access(target, access) != nil {
		g.Enabled = false
		g.InactiveReason = "path_unavailable"
	}
	return g, nil
}
func (s *Store) GetTransferGrant(ctx context.Context, id string) (v entities.TransferPathGrant, err error) {
	err = s.view(ctx, func() error {
		var e error
		v, e = get[entities.TransferPathGrant](s, "grants", id)
		if e == nil {
			v, e = s.effectiveGrant(v)
		}
		return e
	})
	return
}
func (s *Store) ListTransferGrants(ctx context.Context) (out []entities.TransferPathGrant, err error) {
	err = s.view(ctx, func() error {
		ids := keys(s, "grants", "")
		for i := len(ids) - 1; i >= 0; i-- {
			v, e := get[entities.TransferPathGrant](s, "grants", ids[i])
			if e != nil {
				return e
			}
			v, e = s.effectiveGrant(v)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}
func (s *Store) saveGrant(ctx context.Context, g entities.TransferPathGrant, create bool) error {
	return s.update(ctx, func(tx *transaction) error {
		if s.managed {
			return contracts.ErrManagedConfiguration
		}
		_, exists := s.index["grants"][g.ID]
		if !create && !exists {
			return ErrNotFound
		}
		if create && exists {
			return errors.New("grant already exists")
		}
		if _, ok := s.index["mounts"][g.MountID]; !ok {
			return ErrNotFound
		}
		if _, ok := s.index["peers"][g.PeerNodeID]; !ok {
			return ErrNotFound
		}
		for _, id := range keys(s, "grants", g.PeerNodeID) {
			other, e := get[entities.TransferPathGrant](s, "grants", id)
			if e != nil {
				return e
			}
			if id != g.ID && other.MountID == g.MountID && other.Path == g.Path && other.Direction == g.Direction {
				return errors.New("grant already exists")
			}
		}
		if e := tx.put("grants", g.ID, g.PeerNodeID, order(g.CreatedAt), g); e != nil {
			return e
		}
		return tx.audit("grant_saved", g.ID, g)
	})
}
func (s *Store) CreateTransferGrant(ctx context.Context, g entities.TransferPathGrant) error {
	return s.saveGrant(ctx, g, true)
}
func (s *Store) UpdateTransferGrant(ctx context.Context, g entities.TransferPathGrant) error {
	return s.saveGrant(ctx, g, false)
}
func (s *Store) DeleteTransferGrant(ctx context.Context, id, correlation string, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		if s.managed {
			return contracts.ErrManagedConfiguration
		}
		g, e := get[entities.TransferPathGrant](s, "grants", id)
		if e != nil {
			return e
		}
		g.CorrelationID, g.UpdatedAt = correlation, now
		tx.remove("grants", id)
		return tx.audit("grant_deleted", id, g)
	})
}

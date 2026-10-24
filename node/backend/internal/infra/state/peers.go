package state

import (
	"context"
	"errors"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"strings"
	"time"
)

type inviteRecord struct {
	Invite     entities.PairingInvite `yaml:"invite"`
	SecretHash string                 `yaml:"secret_hash"`
}
type requestRecord struct {
	Request    entities.PairingRequest `yaml:"request"`
	SecretHash string                  `yaml:"secret_hash"`
}

func (s *Store) CreatePairingInvite(ctx context.Context, v entities.PairingInvite, hash string) error {
	return s.update(ctx, func(tx *transaction) error {
		if _, ok := s.index["invites"][v.ID]; ok {
			return errors.New("invite already exists")
		}
		return tx.put("invites", v.ID, "", order(v.CreatedAt), inviteRecord{v, hash})
	})
}
func (s *Store) GetPairingInvite(ctx context.Context, id string) (v entities.PairingInvite, err error) {
	err = s.view(ctx, func() error { r, e := get[inviteRecord](s, "invites", id); v = r.Invite; return e })
	return
}
func (s *Store) ListPairingInvites(ctx context.Context) (out []entities.PairingInvite, err error) {
	err = s.view(ctx, func() error {
		ids := keys(s, "invites", "")
		for i := len(ids) - 1; i >= 0; i-- {
			r, e := get[inviteRecord](s, "invites", ids[i])
			if e != nil {
				return e
			}
			out = append(out, r.Invite)
		}
		return nil
	})
	return
}
func (s *Store) RevokePairingInvite(ctx context.Context, id string, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		v, e := get[inviteRecord](s, "invites", id)
		if e != nil {
			return e
		}
		v.Invite.Status, v.Invite.RevokedAt = "revoked", &now
		return tx.put("invites", id, "", order(v.Invite.CreatedAt), v)
	})
}
func (s *Store) CreatePairingRequest(ctx context.Context, v entities.PairingRequest, hash string) error {
	return s.update(ctx, func(tx *transaction) error {
		if _, ok := s.index["requests"][v.ID]; ok {
			return errors.New("request already exists")
		}
		for _, id := range keys(s, "requests", v.InviteID) {
			if id != "" {
				return errors.New("invite already requested")
			}
		}
		return tx.put("requests", v.ID, v.InviteID, order(v.CreatedAt), requestRecord{v, hash})
	})
}
func (s *Store) GetPairingRequest(ctx context.Context, id string) (v entities.PairingRequest, err error) {
	err = s.view(ctx, func() error { r, e := get[requestRecord](s, "requests", id); v = r.Request; return e })
	return
}
func (s *Store) ListPairingRequests(ctx context.Context) (out []entities.PairingRequest, err error) {
	err = s.view(ctx, func() error {
		ids := keys(s, "requests", "")
		for i := len(ids) - 1; i >= 0; i-- {
			r, e := get[requestRecord](s, "requests", ids[i])
			if e != nil {
				return e
			}
			out = append(out, r.Request)
		}
		return nil
	})
	return
}
func (tx *transaction) trust(peer entities.Peer) error {
	peer.IdentityEpoch = max(peer.IdentityEpoch, 1)
	peer.PreviousFingerprint = ""
	peer.ConsecutiveFailures = 0
	peer.LastSeenAt = nil
	return tx.put("peers", peer.NodeID, "", peer.Name, peer)
}
func (s *Store) ApprovePairingInvite(ctx context.Context, id, hash string, peer entities.Peer, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		r, e := get[inviteRecord](s, "invites", id)
		if e != nil {
			return e
		}
		v := r.Invite
		if v.Status != "pending" || r.SecretHash != hash || now.After(v.ExpiresAt) || (v.TargetNodeID != "" && v.TargetNodeID != peer.NodeID) {
			return errors.New("invite cannot be approved")
		}
		if e = tx.trust(peer); e != nil {
			return e
		}
		r.Invite.Status = "consumed"
		return tx.put("invites", id, "", order(v.CreatedAt), r)
	})
}
func (s *Store) ResolvePairingRequest(ctx context.Context, id, status string, peer *entities.Peer, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		r, e := get[requestRecord](s, "requests", id)
		if e != nil {
			return e
		}
		if r.Request.Status != "pending_review" || now.After(r.Request.ExpiresAt) {
			return errors.New("pairing request cannot be resolved")
		}
		if peer != nil {
			if e = tx.trust(*peer); e != nil {
				return e
			}
		}
		r.Request.Status = status
		return tx.put("requests", id, r.Request.InviteID, order(r.Request.CreatedAt), r)
	})
}
func (s *Store) GetPeer(ctx context.Context, id string) (v entities.Peer, err error) {
	err = s.view(ctx, func() error { v, err = get[entities.Peer](s, "peers", id); return err })
	return
}
func (s *Store) ListPeers(ctx context.Context) (out []entities.Peer, err error) {
	err = s.view(ctx, func() error {
		for _, id := range keys(s, "peers", "") {
			v, e := get[entities.Peer](s, "peers", id)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	return
}
func (s *Store) changePeer(ctx context.Context, id string, fn func(*entities.Peer) error) error {
	return s.update(ctx, func(tx *transaction) error {
		v, e := get[entities.Peer](s, "peers", id)
		if e != nil {
			return e
		}
		if e = fn(&v); e != nil {
			return e
		}
		return tx.put("peers", id, "", v.Name, v)
	})
}
func (s *Store) UpdatePeerHealth(ctx context.Context, id, state string, seen *time.Time, failures int) error {
	return s.changePeer(ctx, id, func(v *entities.Peer) error {
		if v.State == "revoked" {
			return ErrNotFound
		}
		v.State, v.LastSeenAt, v.ConsecutiveFailures = state, seen, failures
		return nil
	})
}
func (s *Store) UpdatePeerEndpoints(ctx context.Context, id, endpoint, mtls, correlation string) error {
	return s.changePeer(ctx, id, func(v *entities.Peer) error {
		if v.State == "revoked" {
			return ErrNotFound
		}
		v.Endpoint, v.MTLSEndpoint, v.CorrelationID = endpoint, mtls, correlation
		v.State, v.LastSeenAt, v.ConsecutiveFailures = "unknown", nil, 0
		return nil
	})
}
func (s *Store) RecoverPeerIdentity(ctx context.Context, id, fingerprint, correlation string) error {
	return s.changePeer(ctx, id, func(v *entities.Peer) error {
		if v.State != "identity_changed" {
			return ErrNotFound
		}
		v.Fingerprint, v.PreviousFingerprint, v.CorrelationID = fingerprint, "", correlation
		v.IdentityEpoch++
		v.State, v.LastSeenAt, v.ConsecutiveFailures = "unknown", nil, 0
		return nil
	})
}
func (s *Store) ApplyPeerIdentityHandover(ctx context.Context, id string, previousEpoch int, previousFingerprint string, nextEpoch int, nextFingerprint, correlation string) error {
	return s.changePeer(ctx, id, func(v *entities.Peer) error {
		if v.State == "revoked" || v.IdentityEpoch != previousEpoch || v.Fingerprint != previousFingerprint {
			return ErrNotFound
		}
		v.PreviousFingerprint, v.Fingerprint, v.IdentityEpoch, v.CorrelationID = v.Fingerprint, nextFingerprint, nextEpoch, correlation
		v.State, v.LastSeenAt, v.ConsecutiveFailures = "unknown", nil, 0
		return nil
	})
}
func (s *Store) ConfirmPeerIdentityHandover(ctx context.Context, id string, epoch int, fingerprint string) error {
	return s.changePeer(ctx, id, func(v *entities.Peer) error {
		if v.State == "revoked" || v.IdentityEpoch != epoch || v.Fingerprint != fingerprint || v.PreviousFingerprint == "" {
			return ErrNotFound
		}
		v.PreviousFingerprint = ""
		return nil
	})
}
func (s *Store) RevokePeer(ctx context.Context, id, correlation string, now time.Time) error {
	return s.update(ctx, func(tx *transaction) error {
		peer, e := get[entities.Peer](s, "peers", id)
		if e != nil {
			return e
		}
		peer.State, peer.ConsecutiveFailures, peer.CorrelationID = "revoked", 0, correlation
		if e = tx.put("peers", id, "", peer.Name, peer); e != nil {
			return e
		}
		if e = tx.audit("peer_revoked", id, peer); e != nil {
			return e
		}
		// Removed configuration entries keep their original identity binding.
		// Reintroducing one after re-pairing must not resurrect its permission.
		for _, key := range keys(s, "grant_bindings", "") {
			binding, e := get[string](s, "grant_bindings", key)
			if e != nil {
				return e
			}
			if strings.HasPrefix(binding, id+"\x00") {
				if e = tx.put("revoked_grants", key, id, "", true); e != nil {
					return e
				}
			}
		}
		for _, key := range keys(s, "grants", id) {
			grant, e := get[entities.TransferPathGrant](s, "grants", key)
			if e != nil {
				return e
			}
			if e = tx.put("revoked_grants", key, id, "", true); e != nil {
				return e
			}
			grant.Enabled, grant.UpdatedAt, grant.CorrelationID = false, now, correlation
			if !s.managed {
				if e = tx.put("grants", key, id, order(grant.CreatedAt), grant); e != nil {
					return e
				}
			}
			if e = tx.audit("peer_revoked", key, grant); e != nil {
				return e
			}
		}
		return nil
	})
}

package grants

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

var (
	ErrInvalid  = errors.New("invalid transfer path grant")
	ErrNotFound = errors.New("transfer path grant not found")
	ErrConflict = errors.New("transfer path grant conflicts with an existing grant")
)

type Input struct {
	PeerNodeID       string
	MountID          string
	Path             string
	Direction        string
	Permissions      entities.GrantPermissions
	ConflictPolicies []string
	VisibleToPeer    bool
	Enabled          bool
	CorrelationID    string
}

type Service struct {
	store contracts.Store
	files *filesystem.Service
	now   func() time.Time
}

func New(store contracts.Store, files *filesystem.Service) *Service {
	return &Service{store: store, files: files, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) List(ctx context.Context) ([]entities.TransferPathGrant, error) {
	return s.store.ListTransferGrants(ctx)
}

func (s *Service) Create(ctx context.Context, input Input) (entities.TransferPathGrant, error) {
	grant, err := s.validate(ctx, input)
	if err != nil {
		return grant, err
	}
	existing, err := s.store.ListTransferGrants(ctx)
	if err != nil {
		return grant, err
	}
	for _, item := range existing {
		if item.PeerNodeID == grant.PeerNodeID && item.MountID == grant.MountID &&
			item.Path == grant.Path && item.Direction == grant.Direction {
			return grant, ErrConflict
		}
	}
	now := s.now()
	grant.ID, grant.CreatedAt, grant.UpdatedAt = filesystem.NewID("grant"), now, now
	if err := s.store.CreateTransferGrant(ctx, grant); err != nil {
		return grant, err
	}
	return grant, nil
}

func (s *Service) Update(ctx context.Context, id string, input Input) (entities.TransferPathGrant, error) {
	existing, err := s.store.GetTransferGrant(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return existing, ErrNotFound
	}
	if err != nil {
		return existing, err
	}
	grant, err := s.validate(ctx, input)
	if err != nil {
		return grant, err
	}
	grant.ID, grant.CreatedAt, grant.UpdatedAt = existing.ID, existing.CreatedAt, s.now()
	items, err := s.store.ListTransferGrants(ctx)
	if err != nil {
		return grant, err
	}
	for _, item := range items {
		if item.ID != grant.ID && item.PeerNodeID == grant.PeerNodeID &&
			item.MountID == grant.MountID && item.Path == grant.Path && item.Direction == grant.Direction {
			return grant, ErrConflict
		}
	}
	if err := s.store.UpdateTransferGrant(ctx, grant); errors.Is(err, db.ErrNotFound) {
		return grant, ErrNotFound
	} else if err != nil {
		return grant, err
	}
	return grant, nil
}

func (s *Service) Delete(ctx context.Context, id, correlationID string) error {
	if err := s.store.DeleteTransferGrant(ctx, id, correlationID, s.now()); errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	} else {
		return err
	}
}

func (s *Service) validate(ctx context.Context, input Input) (entities.TransferPathGrant, error) {
	grant := entities.TransferPathGrant{
		PeerNodeID: strings.TrimSpace(input.PeerNodeID), MountID: strings.TrimSpace(input.MountID),
		Path: normalizePath(input.Path), Direction: strings.ToLower(strings.TrimSpace(input.Direction)),
		Permissions: input.Permissions, VisibleToPeer: input.VisibleToPeer, Enabled: input.Enabled,
		CorrelationID: input.CorrelationID,
	}
	if grant.PeerNodeID == "" || grant.MountID == "" {
		return grant, fmt.Errorf("%w: peer_node_id and mount_id are required", ErrInvalid)
	}
	peer, err := s.store.GetPeer(ctx, grant.PeerNodeID)
	if errors.Is(err, db.ErrNotFound) || !trustedPeerState(peer.State) {
		return grant, fmt.Errorf("%w: grant requires the exact trusted peer identity", ErrInvalid)
	}
	if err != nil {
		return grant, err
	}
	mount, err := s.files.GetMount(ctx, grant.MountID)
	if err != nil {
		return grant, fmt.Errorf("%w: mount must already exist", ErrInvalid)
	}
	if !mount.Enabled {
		return grant, fmt.Errorf("%w: mount is disabled", ErrInvalid)
	}
	if grant.VisibleToPeer && !mount.Published {
		return grant, fmt.Errorf("%w: an unpublished mount cannot be visible to a peer", ErrInvalid)
	}
	if _, err := s.files.Metadata(ctx, grant.MountID, grant.Path); err != nil {
		return grant, fmt.Errorf("%w: grant path must exist inside the selected mount", ErrInvalid)
	}
	if err := validateDirection(peer, grant); err != nil {
		return grant, err
	}
	if mount.Mode != "read_write" &&
		(grant.Permissions.Write || grant.Permissions.Delete || grant.Permissions.Rename ||
			grant.Direction == "receive" || grant.Direction == "send_receive") {
		return grant, fmt.Errorf("%w: write capabilities require a read-write mount", ErrInvalid)
	}
	policies, err := normalizePolicies(input.ConflictPolicies, grant.Direction)
	if err != nil {
		return grant, err
	}
	grant.ConflictPolicies = policies
	return grant, nil
}

func trustedPeerState(state string) bool {
	switch state {
	case "trusted", "unknown", "online", "offline", "degraded":
		return true
	default:
		return false
	}
}

func validateDirection(peer entities.Peer, grant entities.TransferPathGrant) error {
	switch grant.Direction {
	case "send":
		if !grant.Permissions.Read || grant.Permissions.Write || grant.Permissions.Delete || grant.Permissions.Rename {
			return fmt.Errorf("%w: send grants require read-only permissions", ErrInvalid)
		}
	case "receive":
		if !grant.Permissions.Write {
			return fmt.Errorf("%w: receive grants require write permission", ErrInvalid)
		}
	case "send_receive":
		if !grant.Permissions.Read || !grant.Permissions.Write {
			return fmt.Errorf("%w: send_receive grants require read and write permissions", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: direction must be send, receive, or send_receive", ErrInvalid)
	}
	if peer.TransferMode == "one_sided" {
		if peer.LocalRole == "sender" && grant.Direction != "send" {
			return fmt.Errorf("%w: local sender role only permits send grants", ErrInvalid)
		}
		if peer.LocalRole == "receiver" && grant.Direction != "receive" {
			return fmt.Errorf("%w: local receiver role only permits receive grants", ErrInvalid)
		}
	}
	return nil
}

func normalizePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.TrimLeft(value, "/")
	clean := path.Clean(value)
	if clean == "" || clean == "/" {
		return "."
	}
	return clean
}

func normalizePolicies(values []string, direction string) ([]string, error) {
	if direction == "send" && len(values) > 0 {
		return nil, fmt.Errorf("%w: conflict policies apply only to receiving grants", ErrInvalid)
	}
	if direction == "send" {
		return []string{}, nil
	}
	if len(values) == 0 {
		return []string{"fail"}, nil
	}
	allowed := map[string]bool{"skip": true, "overwrite": true, "rename": true, "fail": true, "ask": true, "checksum": true}
	unique := make(map[string]bool)
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !allowed[value] {
			return nil, fmt.Errorf("%w: unsupported conflict policy %q", ErrInvalid, value)
		}
		unique[value] = true
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

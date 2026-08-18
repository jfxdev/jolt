package pairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

var (
	ErrInvalid             = errors.New("invalid pairing request")
	ErrNotFound            = errors.New("pairing resource not found")
	ErrExpired             = errors.New("pairing invite expired")
	ErrFingerprintMismatch = errors.New("peer fingerprint does not match")
)

type InviteInput struct {
	TargetNodeID  string
	TransferMode  string
	IssuerRole    string
	InviteeRole   string
	Purpose       string
	ClusterID     string
	ExpiryMinutes int
	CorrelationID string
}

type IncomingRequestInput struct {
	InviteID            string
	InviteToken         string
	IssuerNodeID        string
	IssuerName          string
	IssuerFingerprint   string
	IssuerIdentityEpoch int
	IssuerEndpoint      string
	IssuerMTLSEndpoint  string
	TransferMode        string
	IssuerRole          string
	InviteeRole         string
	Purpose             string
	ClusterID           string
	ExpiresAt           time.Time
	CorrelationID       string
}

type ApproveInviteInput struct {
	InviteToken       string
	PeerNodeID        string
	PeerName          string
	PeerFingerprint   string
	PeerIdentityEpoch int
	PeerEndpoint      string
	PeerMTLSEndpoint  string
	CorrelationID     string
}

type UpdatePeerEndpointsInput struct {
	Endpoint      string
	MTLSEndpoint  string
	CorrelationID string
}

type Service struct {
	store    contracts.Store
	identity entities.Identity
	now      func() time.Time
}

func New(store contracts.Store, identity entities.Identity) *Service {
	return &Service{store: store, identity: identity, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) CreateInvite(ctx context.Context, input InviteInput) (entities.PairingInvite, string, error) {
	if err := validateModeAndRoles(input.TransferMode, input.IssuerRole, input.InviteeRole); err != nil {
		return entities.PairingInvite{}, "", err
	}
	if input.TargetNodeID == s.identity.NodeID {
		return entities.PairingInvite{}, "", fmt.Errorf("%w: target must be another node", ErrInvalid)
	}
	if input.ExpiryMinutes == 0 {
		input.ExpiryMinutes = 20
	}
	if input.ExpiryMinutes < 5 || input.ExpiryMinutes > 1440 {
		return entities.PairingInvite{}, "", fmt.Errorf("%w: expiry_minutes must be between 5 and 1440", ErrInvalid)
	}
	token, err := randomToken()
	if err != nil {
		return entities.PairingInvite{}, "", err
	}
	now := s.now()
	invite := entities.PairingInvite{
		ID: filesystem.NewID("inv"), TargetNodeID: strings.TrimSpace(input.TargetNodeID),
		TransferMode: input.TransferMode, IssuerRole: input.IssuerRole, InviteeRole: input.InviteeRole,
		Purpose: strings.TrimSpace(input.Purpose), ClusterID: strings.TrimSpace(input.ClusterID),
		OneTime: true, Status: "pending", ExpiresAt: now.Add(time.Duration(input.ExpiryMinutes) * time.Minute),
		CreatedAt: now, CorrelationID: input.CorrelationID,
	}
	if err := s.store.CreatePairingInvite(ctx, invite, digest(token)); err != nil {
		return entities.PairingInvite{}, "", err
	}
	return invite, token, nil
}

func (s *Service) ListInvites(ctx context.Context) ([]entities.PairingInvite, error) {
	items, err := s.store.ListPairingInvites(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	for index := range items {
		if items[index].Status == "pending" && now.After(items[index].ExpiresAt) {
			items[index].Status = "expired"
		}
	}
	return items, nil
}

func (s *Service) RevokeInvite(ctx context.Context, id string) error {
	invite, err := s.store.GetPairingInvite(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if s.now().After(invite.ExpiresAt) {
		return ErrExpired
	}
	if err := s.store.RevokePairingInvite(ctx, id, s.now()); errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	} else {
		return err
	}
}

func (s *Service) CreateIncomingRequest(ctx context.Context, input IncomingRequestInput) (entities.PairingRequest, error) {
	if err := validateModeAndRoles(input.TransferMode, input.IssuerRole, input.InviteeRole); err != nil {
		return entities.PairingRequest{}, err
	}
	if strings.TrimSpace(input.InviteID) == "" || len(input.InviteToken) < 32 ||
		strings.TrimSpace(input.IssuerNodeID) == "" || strings.TrimSpace(input.IssuerFingerprint) == "" ||
		strings.TrimSpace(input.IssuerEndpoint) == "" || strings.TrimSpace(input.IssuerMTLSEndpoint) == "" {
		return entities.PairingRequest{}, fmt.Errorf("%w: issuer identity, control/mTLS endpoints, invite id and token are required", ErrInvalid)
	}
	if input.IssuerNodeID == s.identity.NodeID {
		return entities.PairingRequest{}, fmt.Errorf("%w: issuer must be another node", ErrInvalid)
	}
	now := s.now()
	if !input.ExpiresAt.After(now) {
		return entities.PairingRequest{}, ErrExpired
	}
	request := entities.PairingRequest{
		ID: filesystem.NewID("preq"), InviteID: input.InviteID,
		IssuerNodeID: input.IssuerNodeID, IssuerName: strings.TrimSpace(input.IssuerName),
		IssuerFingerprint: input.IssuerFingerprint, IssuerIdentityEpoch: max(input.IssuerIdentityEpoch, 1),
		IssuerEndpoint:     strings.TrimRight(input.IssuerEndpoint, "/"),
		IssuerMTLSEndpoint: strings.TrimRight(input.IssuerMTLSEndpoint, "/"),
		TransferMode:       input.TransferMode, IssuerRole: input.IssuerRole, InviteeRole: input.InviteeRole,
		Purpose: strings.TrimSpace(input.Purpose), ClusterID: strings.TrimSpace(input.ClusterID),
		Status: "pending_review", ExpiresAt: input.ExpiresAt, CreatedAt: now, CorrelationID: input.CorrelationID,
	}
	if err := s.store.CreatePairingRequest(ctx, request, digest(input.InviteToken)); err != nil {
		return entities.PairingRequest{}, err
	}
	return request, nil
}

func (s *Service) ListRequests(ctx context.Context) ([]entities.PairingRequest, error) {
	items, err := s.store.ListPairingRequests(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	for index := range items {
		if items[index].Status == "pending_review" && now.After(items[index].ExpiresAt) {
			items[index].Status = "expired"
		}
	}
	return items, nil
}

func (s *Service) ApproveInvite(ctx context.Context, id string, input ApproveInviteInput) (entities.Peer, error) {
	invite, err := s.store.GetPairingInvite(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrNotFound
	}
	if err != nil {
		return entities.Peer{}, err
	}
	now := s.now()
	if now.After(invite.ExpiresAt) {
		return entities.Peer{}, ErrExpired
	}
	if input.PeerNodeID == "" || input.PeerFingerprint == "" || input.PeerEndpoint == "" ||
		input.PeerMTLSEndpoint == "" || len(input.InviteToken) < 32 {
		return entities.Peer{}, fmt.Errorf("%w: peer identity, control/mTLS endpoints and invite token are required", ErrInvalid)
	}
	peer := entities.Peer{
		NodeID: input.PeerNodeID, Name: strings.TrimSpace(input.PeerName),
		Fingerprint: input.PeerFingerprint, IdentityEpoch: max(input.PeerIdentityEpoch, 1),
		Endpoint:     strings.TrimRight(input.PeerEndpoint, "/"),
		MTLSEndpoint: strings.TrimRight(input.PeerMTLSEndpoint, "/"),
		TransferMode: invite.TransferMode, LocalRole: invite.IssuerRole, RemoteRole: invite.InviteeRole,
		ClusterID: invite.ClusterID, State: "trusted", TrustedAt: now, CorrelationID: input.CorrelationID,
	}
	if err := s.store.ApprovePairingInvite(ctx, id, digest(input.InviteToken), peer, now); err != nil {
		return entities.Peer{}, fmt.Errorf("%w: invite token, status or target is invalid", ErrInvalid)
	}
	return peer, nil
}

func (s *Service) AcceptRequest(ctx context.Context, id, confirmedFingerprint, correlationID string) (entities.Peer, error) {
	request, err := s.store.GetPairingRequest(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrNotFound
	}
	if err != nil {
		return entities.Peer{}, err
	}
	if s.now().After(request.ExpiresAt) {
		return entities.Peer{}, ErrExpired
	}
	if confirmedFingerprint == "" || confirmedFingerprint != request.IssuerFingerprint {
		return entities.Peer{}, ErrFingerprintMismatch
	}
	now := s.now()
	peer := entities.Peer{
		NodeID: request.IssuerNodeID, Name: request.IssuerName, Fingerprint: request.IssuerFingerprint,
		IdentityEpoch: request.IssuerIdentityEpoch,
		Endpoint:      request.IssuerEndpoint, MTLSEndpoint: request.IssuerMTLSEndpoint, TransferMode: request.TransferMode,
		LocalRole: request.InviteeRole, RemoteRole: request.IssuerRole,
		ClusterID: request.ClusterID, State: "trusted", TrustedAt: now, CorrelationID: correlationID,
	}
	if err := s.store.ResolvePairingRequest(ctx, id, "accepted", &peer, now); err != nil {
		return entities.Peer{}, fmt.Errorf("%w: request is no longer pending", ErrInvalid)
	}
	return peer, nil
}

func (s *Service) RejectRequest(ctx context.Context, id string) error {
	request, err := s.store.GetPairingRequest(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if s.now().After(request.ExpiresAt) {
		return ErrExpired
	}
	if err := s.store.ResolvePairingRequest(ctx, id, "rejected", nil, s.now()); err != nil {
		return fmt.Errorf("%w: request is no longer pending", ErrInvalid)
	}
	return nil
}

func (s *Service) ListPeers(ctx context.Context) ([]entities.Peer, error) {
	return s.store.ListPeers(ctx)
}

func (s *Service) RevokePeer(ctx context.Context, nodeID, correlationID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || nodeID == s.identity.NodeID {
		return ErrInvalid
	}
	if _, err := s.store.GetPeer(ctx, nodeID); errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if err := s.store.RevokePeer(ctx, nodeID, correlationID, s.now()); errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	} else {
		return err
	}
}

func (s *Service) UpdatePeerEndpoints(ctx context.Context, nodeID string,
	input UpdatePeerEndpointsInput) (entities.Peer, error) {
	nodeID = strings.TrimSpace(nodeID)
	peer, err := s.store.GetPeer(ctx, nodeID)
	if errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrNotFound
	}
	if err != nil {
		return entities.Peer{}, err
	}
	if peer.State == "revoked" {
		return entities.Peer{}, fmt.Errorf("%w: revoked peer endpoints cannot be updated", ErrInvalid)
	}
	endpoint, err := normalizePeerEndpoint(input.Endpoint, false)
	if err != nil {
		return entities.Peer{}, err
	}
	mtlsEndpoint, err := normalizePeerEndpoint(input.MTLSEndpoint, true)
	if err != nil {
		return entities.Peer{}, err
	}
	if err := s.store.UpdatePeerEndpoints(ctx, nodeID, endpoint, mtlsEndpoint, input.CorrelationID); errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrNotFound
	} else if err != nil {
		return entities.Peer{}, err
	}
	peer.Endpoint, peer.MTLSEndpoint = endpoint, mtlsEndpoint
	peer.State, peer.LastSeenAt, peer.ConsecutiveFailures = "unknown", nil, 0
	peer.CorrelationID = input.CorrelationID
	return peer, nil
}

func (s *Service) RecoverPeerIdentity(ctx context.Context, nodeID, confirmedFingerprint,
	correlationID string) (entities.Peer, error) {
	nodeID, confirmedFingerprint = strings.TrimSpace(nodeID), strings.TrimSpace(confirmedFingerprint)
	peer, err := s.store.GetPeer(ctx, nodeID)
	if errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrNotFound
	}
	if err != nil {
		return entities.Peer{}, err
	}
	if peer.State != "identity_changed" || confirmedFingerprint == "" ||
		confirmedFingerprint == peer.Fingerprint {
		return entities.Peer{}, fmt.Errorf("%w: identity recovery requires a different manually confirmed fingerprint", ErrInvalid)
	}
	if err := s.store.RecoverPeerIdentity(ctx, nodeID, confirmedFingerprint, correlationID); errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrInvalid
	} else if err != nil {
		return entities.Peer{}, err
	}
	peer.Fingerprint, peer.State = confirmedFingerprint, "unknown"
	peer.IdentityEpoch++
	peer.LastSeenAt, peer.ConsecutiveFailures, peer.CorrelationID = nil, 0, correlationID
	return peer, nil
}

func (s *Service) ApplyIdentityHandover(ctx context.Context, handover joltcrypto.IdentityHandover,
	correlationID string) (entities.Peer, error) {
	if err := joltcrypto.VerifyIdentityHandover(handover, s.now()); err != nil {
		return entities.Peer{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	peer, err := s.store.GetPeer(ctx, handover.NodeID)
	if errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrNotFound
	}
	if err != nil {
		return entities.Peer{}, err
	}
	if peer.State == "revoked" || peer.IdentityEpoch != handover.PreviousEpoch ||
		peer.Fingerprint != handover.PreviousFingerprint {
		return entities.Peer{}, fmt.Errorf("%w: handover does not continue the exact trusted identity epoch", ErrInvalid)
	}
	if err := s.store.ApplyPeerIdentityHandover(ctx, peer.NodeID, handover.PreviousEpoch,
		handover.PreviousFingerprint, handover.NextEpoch, handover.NextFingerprint,
		correlationID); errors.Is(err, db.ErrNotFound) {
		return entities.Peer{}, ErrInvalid
	} else if err != nil {
		return entities.Peer{}, err
	}
	peer.PreviousFingerprint, peer.Fingerprint = peer.Fingerprint, handover.NextFingerprint
	peer.IdentityEpoch, peer.State = handover.NextEpoch, "unknown"
	peer.LastSeenAt, peer.ConsecutiveFailures, peer.CorrelationID = nil, 0, correlationID
	return peer, nil
}

func normalizePeerEndpoint(value string, mtls bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || (mtls && parsed.Scheme != "https") {
		return "", fmt.Errorf("%w: valid HTTP control and HTTPS mTLS endpoints are required", ErrInvalid)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func validateModeAndRoles(mode, issuerRole, inviteeRole string) error {
	switch mode {
	case "dual_channel":
		if issuerRole != "sender_receiver" || inviteeRole != "sender_receiver" {
			return fmt.Errorf("%w: dual_channel requires sender_receiver on both sides", ErrInvalid)
		}
	case "one_sided":
		if !oneSidedRole(issuerRole) || !oneSidedRole(inviteeRole) || issuerRole == inviteeRole {
			return fmt.Errorf("%w: one_sided requires different valid roles", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: transfer_mode must be one_sided or dual_channel", ErrInvalid)
	}
	return nil
}

func oneSidedRole(value string) bool {
	return value == "sender" || value == "receiver" || value == "requester"
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

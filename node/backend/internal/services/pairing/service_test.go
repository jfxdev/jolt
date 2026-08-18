package pairing

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
)

func testService(t *testing.T, nodeID string) *Service {
	t.Helper()
	storage, err := db.Open(filepath.Join(t.TempDir(), "pairing.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	return New(storage, entities.Identity{NodeID: nodeID, Fingerprint: "AA:BB"})
}

func TestSignedIdentityHandoverAdvancesExactTrustedEpochAndRejectsReplay(t *testing.T) {
	service := testService(t, "local")
	peerKeys := t.TempDir()
	current, err := joltcrypto.LoadOrCreate(peerKeys)
	if err != nil {
		t.Fatal(err)
	}
	invite, token, err := service.CreateInvite(context.Background(), InviteInput{
		TargetNodeID: current.NodeID, TransferMode: "dual_channel",
		IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApproveInvite(context.Background(), invite.ID, ApproveInviteInput{
		InviteToken: token, PeerNodeID: current.NodeID, PeerName: "Rotating peer",
		PeerFingerprint: current.Fingerprint, PeerIdentityEpoch: current.Epoch,
		PeerEndpoint: "https://peer.test", PeerMTLSEndpoint: "https://peer.test:8443",
	}); err != nil {
		t.Fatal(err)
	}
	next, err := joltcrypto.RotateIdentity(peerKeys, current, current.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	handovers, err := joltcrypto.LoadIdentityHandovers(peerKeys)
	if err != nil || len(handovers) != 1 {
		t.Fatalf("handovers=%+v err=%v", handovers, err)
	}
	updated, err := service.ApplyIdentityHandover(context.Background(), handovers[0], "cor-handover")
	if err != nil {
		t.Fatal(err)
	}
	if updated.NodeID != current.NodeID || updated.Fingerprint != next.Fingerprint ||
		updated.PreviousFingerprint != current.Fingerprint ||
		updated.IdentityEpoch != next.Epoch || updated.State != "unknown" {
		t.Fatalf("updated peer=%+v", updated)
	}
	if _, err := service.ApplyIdentityHandover(context.Background(), handovers[0], "cor-replay"); err == nil {
		t.Fatal("replayed handover was accepted")
	}
	persisted, err := service.store.GetPeer(context.Background(), current.NodeID)
	if err != nil || persisted.Fingerprint != next.Fingerprint || persisted.IdentityEpoch != next.Epoch {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	if err := service.store.ConfirmPeerIdentityHandover(context.Background(), current.NodeID,
		next.Epoch, next.Fingerprint); err != nil {
		t.Fatal(err)
	}
	persisted, err = service.store.GetPeer(context.Background(), current.NodeID)
	if err != nil || persisted.PreviousFingerprint != "" {
		t.Fatalf("previous identity was not retired: persisted=%+v err=%v", persisted, err)
	}
}

func TestInviteAndIncomingRequestRemainPending(t *testing.T) {
	issuer := testService(t, "issuer-node")
	invite, token, err := issuer.CreateInvite(context.Background(), InviteInput{
		TargetNodeID: "target-node", TransferMode: "dual_channel",
		IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
		Purpose: "manual-library-exchange", ClusterID: "home", ExpiryMinutes: 20, CorrelationID: "cor-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || invite.Status != "pending" {
		t.Fatalf("unexpected invite: %#v", invite)
	}

	target := testService(t, "target-node")
	request, err := target.CreateIncomingRequest(context.Background(), IncomingRequestInput{
		InviteID: invite.ID, InviteToken: token, IssuerNodeID: "issuer-node",
		IssuerName: "Issuer", IssuerFingerprint: "AA:BB", IssuerEndpoint: "https://issuer.test",
		IssuerMTLSEndpoint: "https://issuer.test:8443",
		TransferMode:       invite.TransferMode, IssuerRole: invite.IssuerRole, InviteeRole: invite.InviteeRole,
		Purpose: invite.Purpose, ClusterID: invite.ClusterID, ExpiresAt: invite.ExpiresAt, CorrelationID: "cor-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.Status != "pending_review" {
		t.Fatalf("request status = %q", request.Status)
	}
	if _, err := issuer.ApproveInvite(context.Background(), invite.ID, ApproveInviteInput{
		InviteToken: token, PeerNodeID: "target-node", PeerName: "Target",
		PeerFingerprint: "CC:DD", PeerEndpoint: "https://target.test",
		PeerMTLSEndpoint: "https://target.test:8443",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := target.AcceptRequest(context.Background(), request.ID, "AA:BB", "cor-2"); err != nil {
		t.Fatal(err)
	}
	issuerPeers, err := issuer.ListPeers(context.Background())
	if err != nil || len(issuerPeers) != 1 || issuerPeers[0].NodeID != "target-node" || issuerPeers[0].ClusterID != "home" {
		t.Fatalf("issuer peers = %#v, error = %v", issuerPeers, err)
	}
	targetPeers, err := target.ListPeers(context.Background())
	if err != nil || len(targetPeers) != 1 || targetPeers[0].NodeID != "issuer-node" || targetPeers[0].ClusterID != "home" {
		t.Fatalf("target peers = %#v, error = %v", targetPeers, err)
	}
}

func TestExpiredIncomingRequestIsRejected(t *testing.T) {
	service := testService(t, "target-node")
	_, err := service.CreateIncomingRequest(context.Background(), IncomingRequestInput{
		InviteID: "inv", InviteToken: "abcdefghijklmnopqrstuvwxyz-1234567890",
		IssuerNodeID: "issuer", IssuerName: "Issuer", IssuerFingerprint: "AA",
		IssuerEndpoint: "https://issuer.test", IssuerMTLSEndpoint: "https://issuer.test:8443", TransferMode: "one_sided",
		IssuerRole: "sender", InviteeRole: "receiver", ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != ErrExpired {
		t.Fatalf("error = %v, want ErrExpired", err)
	}
}

func TestDualChannelRequiresSymmetricRoles(t *testing.T) {
	service := testService(t, "issuer")
	_, _, err := service.CreateInvite(context.Background(), InviteInput{
		TargetNodeID: "target", TransferMode: "dual_channel",
		IssuerRole: "sender", InviteeRole: "receiver",
	})
	if err == nil {
		t.Fatal("expected role validation error")
	}
}

func TestAcceptanceRequiresExactFingerprint(t *testing.T) {
	service := testService(t, "target")
	request, err := service.CreateIncomingRequest(context.Background(), IncomingRequestInput{
		InviteID: "inv", InviteToken: "abcdefghijklmnopqrstuvwxyz-1234567890",
		IssuerNodeID: "issuer", IssuerName: "Issuer", IssuerFingerprint: "AA:BB",
		IssuerEndpoint: "https://issuer.test", IssuerMTLSEndpoint: "https://issuer.test:8443", TransferMode: "one_sided",
		IssuerRole: "sender", InviteeRole: "receiver", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.AcceptRequest(context.Background(), request.ID, "CC:DD", "cor"); err != ErrFingerprintMismatch {
		t.Fatalf("error = %v, want ErrFingerprintMismatch", err)
	}
	peers, err := service.ListPeers(context.Background())
	if err != nil || len(peers) != 0 {
		t.Fatalf("peers = %#v, error = %v", peers, err)
	}
}

func TestRevokePeerDisablesTrustAndAllRelatedGrants(t *testing.T) {
	service := testService(t, "issuer")
	invite, token, err := service.CreateInvite(context.Background(), InviteInput{
		TargetNodeID: "target", TransferMode: "dual_channel",
		IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApproveInvite(context.Background(), invite.ID, ApproveInviteInput{
		InviteToken: token, PeerNodeID: "target", PeerName: "Target",
		PeerFingerprint: "CC:DD", PeerEndpoint: "https://target.test",
		PeerMTLSEndpoint: "https://target.test:8443",
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := service.store.UpsertMount(context.Background(), entities.Mount{
		ID: "media", Name: "Media", LocalPath: t.TempDir(), TargetType: "directory",
		Mode: "read_write", Published: true, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.store.CreateTransferGrant(context.Background(), entities.TransferPathGrant{
		ID: "grant-1", PeerNodeID: "target", MountID: "media", Path: ".",
		Direction: "send_receive", Permissions: entities.GrantPermissions{Read: true, Write: true},
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	updated, err := service.UpdatePeerEndpoints(context.Background(), "target", UpdatePeerEndpointsInput{
		Endpoint: "http://target-new.test:8080/", MTLSEndpoint: "https://target-new.test:8443/",
		CorrelationID: "cor-endpoints",
	})
	if err != nil || updated.Endpoint != "http://target-new.test:8080" ||
		updated.MTLSEndpoint != "https://target-new.test:8443" || updated.State != "unknown" {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	if err := service.store.UpdatePeerHealth(context.Background(), "target", "identity_changed", nil, 1); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.RecoverPeerIdentity(context.Background(), "target", "EE:FF", "cor-recover")
	if err != nil || recovered.Fingerprint != "EE:FF" || recovered.State != "unknown" {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if _, err := service.RecoverPeerIdentity(context.Background(), "target", "11:22", ""); err == nil {
		t.Fatal("identity recovery was allowed outside identity_changed")
	}
	if _, err := service.UpdatePeerEndpoints(context.Background(), "target", UpdatePeerEndpointsInput{
		Endpoint: "file:///etc/passwd", MTLSEndpoint: "http://target.test:8443",
	}); err == nil {
		t.Fatal("unsafe endpoints were accepted")
	}
	if err := service.RevokePeer(context.Background(), "target", "cor-revoke"); err != nil {
		t.Fatal(err)
	}
	peer, err := service.store.GetPeer(context.Background(), "target")
	if err != nil || peer.State != "revoked" || peer.CorrelationID != "cor-revoke" {
		t.Fatalf("peer=%+v err=%v", peer, err)
	}
	seen := time.Now().UTC()
	if err := service.store.UpdatePeerHealth(context.Background(), "target", "online", &seen, 0); err == nil {
		t.Fatal("revoked peer health was unexpectedly updated")
	}
	peer, err = service.store.GetPeer(context.Background(), "target")
	if err != nil || peer.State != "revoked" {
		t.Fatalf("peer trust was restored by heartbeat: peer=%+v err=%v", peer, err)
	}
	grant, err := service.store.GetTransferGrant(context.Background(), "grant-1")
	if err != nil || grant.Enabled || grant.CorrelationID != "cor-revoke" {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
	if _, err := service.UpdatePeerEndpoints(context.Background(), "target", UpdatePeerEndpointsInput{
		Endpoint: "https://target.test", MTLSEndpoint: "https://target.test:8443",
	}); err == nil {
		t.Fatal("revoked peer endpoints were updated")
	}
}

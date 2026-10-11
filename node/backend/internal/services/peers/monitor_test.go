package peers

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
)

func TestHeartbeatRequiresConsecutiveFailuresBeforeOffline(t *testing.T) {
	root := t.TempDir()
	store, err := db.Open(filepath.Join(root, "jolt.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := joltcrypto.LoadOrCreate(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	pairingService := pairing.New(store, identity)
	request, err := pairingService.CreateIncomingRequest(context.Background(), pairing.IncomingRequestInput{
		InviteID: "invite-peer", InviteToken: "12345678901234567890123456789012",
		IssuerNodeID: "remote-node", IssuerName: "Remote", IssuerFingerprint: "AA:BB",
		IssuerEndpoint: "https://control.invalid", IssuerMTLSEndpoint: "https://peer.invalid:8443",
		TransferMode: "dual_channel", IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairingService.AcceptRequest(context.Background(), request.ID, "AA:BB", "cor-accept"); err != nil {
		t.Fatal(err)
	}
	certificates, err := joltcrypto.LoadOrCreateCertificateManager(filepath.Join(root, "keys"), identity, store)
	if err != nil {
		t.Fatal(err)
	}
	monitor := NewMonitor(store, certificates, time.Second, time.Second, 3,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	monitor.ConfigureDialContext(func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("peer unreachable")
	})

	peer, err := store.GetPeer(context.Background(), "remote-node")
	if err != nil {
		t.Fatal(err)
	}
	monitor.check(context.Background(), peer)
	peer, _ = store.GetPeer(context.Background(), peer.NodeID)
	if peer.State != "degraded" || peer.ConsecutiveFailures != 1 {
		t.Fatalf("first failure should degrade without marking offline: %+v", peer)
	}
	monitor.check(context.Background(), peer)
	peer, _ = store.GetPeer(context.Background(), peer.NodeID)
	monitor.check(context.Background(), peer)
	peer, _ = store.GetPeer(context.Background(), peer.NodeID)
	if peer.State != "offline" || peer.ConsecutiveFailures != 3 {
		t.Fatalf("third consecutive failure should mark offline: %+v", peer)
	}
}

// A peer whose mTLS listener refuses our certificate has revoked us; it is not
// merely unreachable. Reporting that as "offline" is what made a revocation on
// the far side look like a network fault for weeks.
func TestHeartbeatMarksPeerThatRejectsOurCertificate(t *testing.T) {
	// The far side is a real node that has no peer row for us, so its own
	// verification rejects the handshake and sends a bad-certificate alert.
	// Its identity is the one we trust, so our client-side verification
	// passes and the only failure is the peer's refusal.
	peerRoot := t.TempDir()
	peerStore, err := db.Open(filepath.Join(peerRoot, "jolt.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer peerStore.Close()
	peerIdentity, err := joltcrypto.LoadOrCreate(filepath.Join(peerRoot, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	peerCertificates, err := joltcrypto.LoadOrCreateCertificateManager(
		filepath.Join(peerRoot, "keys"), peerIdentity, peerStore)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.NotFoundHandler()}
	go func() { _ = server.Serve(tls.NewListener(listener, peerCertificates.TLSConfig())) }()
	t.Cleanup(func() { _ = server.Close() })

	root := t.TempDir()
	store, err := db.Open(filepath.Join(root, "jolt.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	identity, err := joltcrypto.LoadOrCreate(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	pairingService := pairing.New(store, identity)
	request, err := pairingService.CreateIncomingRequest(context.Background(), pairing.IncomingRequestInput{
		InviteID: "invite-peer", InviteToken: "12345678901234567890123456789012",
		IssuerNodeID: peerIdentity.NodeID, IssuerName: "Remote",
		IssuerFingerprint: peerIdentity.Fingerprint, IssuerIdentityEpoch: peerIdentity.Epoch,
		IssuerEndpoint: "https://control.invalid", IssuerMTLSEndpoint: "https://peer.invalid:8443",
		TransferMode: "dual_channel", IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairingService.AcceptRequest(context.Background(), request.ID,
		peerIdentity.Fingerprint, "cor-accept"); err != nil {
		t.Fatal(err)
	}
	certificates, err := joltcrypto.LoadOrCreateCertificateManager(filepath.Join(root, "keys"), identity, store)
	if err != nil {
		t.Fatal(err)
	}

	monitor := NewMonitor(store, certificates, time.Second, 5*time.Second, 3,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	monitor.ConfigureDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})

	peer, err := store.GetPeer(context.Background(), peerIdentity.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	monitor.check(context.Background(), peer)
	peer, err = store.GetPeer(context.Background(), peerIdentity.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if peer.State != entities.PeerStateRevokedByPeer {
		t.Fatalf("state = %q, want %q", peer.State, entities.PeerStateRevokedByPeer)
	}
}

package peers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
)

func TestHeartbeatRequiresConsecutiveFailuresBeforeOffline(t *testing.T) {
	root := t.TempDir()
	store, err := db.Open(filepath.Join(root, "jolt.db"))
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

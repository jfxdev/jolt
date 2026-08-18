package grants

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
)

func grantTestService(t *testing.T, mountMode string) (*Service, *filesystem.Service, string) {
	return grantTestServiceWithRoles(t, mountMode, "dual_channel", "sender_receiver", "sender_receiver")
}

func grantTestServiceWithRoles(t *testing.T, mountMode, transferMode, issuerRole, inviteeRole string) (*Service, *filesystem.Service, string) {
	t.Helper()
	storage, err := db.Open(filepath.Join(t.TempDir(), "grants.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	files := filesystem.New(storage)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o755); err != nil {
		t.Fatal(err)
	}
	mount, err := files.SaveMount(context.Background(), entities.Mount{
		Name: "files", LocalPath: root, Mode: mountMode, Published: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pairingService := pairing.New(storage, entities.Identity{NodeID: "local", Fingerprint: "LOCAL"})
	request, err := pairingService.CreateIncomingRequest(context.Background(), pairing.IncomingRequestInput{
		InviteID: "invite", InviteToken: "abcdefghijklmnopqrstuvwxyz-1234567890",
		IssuerNodeID: "trusted-peer", IssuerName: "Trusted", IssuerFingerprint: "PEER",
		IssuerEndpoint: "https://peer.test", IssuerMTLSEndpoint: "https://peer.test:8443", TransferMode: transferMode,
		IssuerRole: issuerRole, InviteeRole: inviteeRole,
		ClusterID: "home", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairingService.AcceptRequest(context.Background(), request.ID, "PEER", "cor-pair"); err != nil {
		t.Fatal(err)
	}
	return New(storage, files), files, mount.ID
}

func TestGrantRequiresTrustedPeerAndExistingMountPath(t *testing.T) {
	service, _, mountID := grantTestService(t, "read_write")
	input := Input{
		PeerNodeID: "unknown-peer", MountID: mountID, Path: "incoming",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"fail"}, VisibleToPeer: true, Enabled: true,
	}
	if _, err := service.Create(context.Background(), input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown peer error=%v, want ErrInvalid", err)
	}
	input.PeerNodeID, input.Path = "trusted-peer", "../outside"
	if _, err := service.Create(context.Background(), input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("traversal error=%v, want ErrInvalid", err)
	}
}

func TestGrantPersistsAndBlocksMountDeletionUntilRevoked(t *testing.T) {
	service, files, mountID := grantTestService(t, "read_write")
	grant, err := service.Create(context.Background(), Input{
		PeerNodeID: "trusted-peer", MountID: mountID, Path: "/incoming",
		Direction:        "receive",
		Permissions:      entities.GrantPermissions{Read: true, Write: true, Rename: true},
		ConflictPolicies: []string{"rename", "ask", "rename"},
		VisibleToPeer:    true, Enabled: true, CorrelationID: "cor-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.Path != "incoming" || len(grant.ConflictPolicies) != 2 {
		t.Fatalf("unexpected normalized grant: %+v", grant)
	}
	items, err := service.List(context.Background())
	if err != nil || len(items) != 1 || items[0].PeerNodeID != "trusted-peer" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	if err := files.DeleteMount(context.Background(), mountID); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatalf("delete mount error=%v, want ErrConflict", err)
	}
	if err := service.Delete(context.Background(), grant.ID, "cor-delete"); err != nil {
		t.Fatal(err)
	}
	if err := files.DeleteMount(context.Background(), mountID); err != nil {
		t.Fatalf("mount should be deletable after grant revocation: %v", err)
	}
}

func TestGrantCannotExceedMountPermissions(t *testing.T) {
	service, _, mountID := grantTestService(t, "read_only")
	_, err := service.Create(context.Background(), Input{
		PeerNodeID: "trusted-peer", MountID: mountID, Path: "incoming",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		VisibleToPeer: true, Enabled: true,
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("read-only mount error=%v, want ErrInvalid", err)
	}
}

func TestOneSidedReceiverCannotGrantSendEvenInsideSameCluster(t *testing.T) {
	service, _, mountID := grantTestServiceWithRoles(t, "read_write", "one_sided", "sender", "receiver")
	_, err := service.Create(context.Background(), Input{
		PeerNodeID: "trusted-peer", MountID: mountID, Path: "incoming",
		Direction: "send", Permissions: entities.GrantPermissions{Read: true},
		VisibleToPeer: true, Enabled: true,
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("one-sided direction error=%v, want ErrInvalid", err)
	}
}

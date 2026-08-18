package recovery_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/infra/recovery"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
)

func TestNodeRestoreDiagnosticsValidateIdentityMountGrantJobAndPartial(t *testing.T) {
	root := t.TempDir()
	dataDir, keysDir, mountDir := filepath.Join(root, "data"), filepath.Join(root, "keys"), filepath.Join(root, "mount")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(mountDir, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := joltcrypto.LoadOrCreate(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := db.Open(filepath.Join(dataDir, "jolt.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mount := entities.Mount{
		ID: "mount_restore", Name: "Restore", LocalPath: mountDir, TargetType: "directory",
		Mode: "read_write", Published: true, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.UpsertMount(context.Background(), mount); err != nil {
		t.Fatal(err)
	}
	pairingService := pairing.New(storage, identity)
	invite, token, err := pairingService.CreateInvite(context.Background(), pairing.InviteInput{
		TargetNodeID: "peer_restore", TransferMode: "dual_channel",
		IssuerRole: "sender_receiver", InviteeRole: "sender_receiver",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairingService.ApproveInvite(context.Background(), invite.ID, pairing.ApproveInviteInput{
		InviteToken: token, PeerNodeID: "peer_restore", PeerName: "Peer",
		PeerFingerprint: "AAAA:BBBB", PeerEndpoint: "https://peer.test",
		PeerMTLSEndpoint: "https://peer.test:8443",
	}); err != nil {
		t.Fatal(err)
	}
	grant := entities.TransferPathGrant{
		ID: "grant_restore", PeerNodeID: "peer_restore", MountID: mount.ID, Path: ".",
		Direction: "receive", Permissions: entities.GrantPermissions{Write: true},
		ConflictPolicies: []string{"overwrite"}, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateTransferGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	job := entities.Job{
		ID: "job_restore", Type: "transfer_pull", State: "waiting_validation",
		Phase: "waiting_validation", MountID: mount.ID, PeerNodeID: "peer_restore",
		SourceGrantID: "remote_grant", DestinationGrantID: grant.ID,
		Destination: "incoming/movie.bin", BytesTotal: 8, BytesCompleted: 4,
		MaxAttempts: 3, CorrelationID: "restore-test", CreatedAt: now, UpdatedAt: now,
	}
	if _, _, err := storage.CreateJob(context.Background(), job, ""); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(mountDir, "incoming", ".jolt-job_restore.partial")
	if err := os.WriteFile(partial, []byte("part"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	report, err := recovery.DiagnoseRestore(context.Background(), dataDir, keysDir,
		identity.NodeID, identity.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" || report.DatabaseIntegrity != "ok" ||
		report.JobCount != 1 || report.JobsRequiringValidation != 1 ||
		len(report.Partials) != 1 || report.Partials[0].State != "valid" {
		t.Fatalf("unexpected restore report: %+v", report)
	}
}

func TestNodeRestoreDiagnosticsReportBlockingDivergence(t *testing.T) {
	root := t.TempDir()
	dataDir, keysDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := joltcrypto.LoadOrCreate(keysDir); err != nil {
		t.Fatal(err)
	}
	storage, err := db.Open(filepath.Join(dataDir, "jolt.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := storage.UpsertMount(context.Background(), entities.Mount{
		ID: "missing_mount", Name: "Missing", LocalPath: filepath.Join(root, "not-restored"),
		TargetType: "directory", Mode: "read_write", Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := recovery.DiagnoseRestore(context.Background(), dataDir, keysDir,
		"wrong-node-id", "WRONG:FINGERPRINT")
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "error" || !hasIssue(report.Issues, "node_id_mismatch") ||
		!hasIssue(report.Issues, "fingerprint_mismatch") ||
		!hasIssue(report.Issues, "mount_missing") {
		t.Fatalf("expected blocking restore issues: %+v", report)
	}
}

func hasIssue(issues []recovery.DiagnosticIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

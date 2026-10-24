package recovery_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/recovery"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
)

func TestNodeSnapshotContainsConsistentStateKeysAndManifest(t *testing.T) {
	root := t.TempDir()
	dataDir, keysDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := joltcrypto.LoadOrCreate(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := db.Open(dataDir, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "desired.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(root, "backups", "node.tar.gz")
	manifest, err := recovery.CreateSnapshot(context.Background(), dataDir, keysDir, output, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Kind != "jolt_node" || manifest.StateIntegrity != "ok" ||
		manifest.NodeID != identity.NodeID || manifest.Fingerprint != identity.Fingerprint {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode=%o want=600", info.Mode().Perm())
	}
	entries := readArchive(t, output)
	for _, expected := range []string{"manifest.json", "data/store.yaml", "keys/identity.json"} {
		if _, exists := entries[expected]; !exists {
			t.Fatalf("archive is missing %s: %v", expected, entries)
		}
	}
	if _, exists := entries["data/jolt.db-wal"]; exists {
		t.Fatal("snapshot contains a transient SQLite WAL")
	}
	var archived ManifestAlias
	if err := json.Unmarshal(entries["manifest.json"], &archived); err != nil {
		t.Fatal(err)
	}
	if archived.NodeID != identity.NodeID || len(archived.Files) < 2 {
		t.Fatalf("unexpected archived manifest: %+v", archived)
	}
}

func TestNodeSnapshotRefusesActiveInstanceAndExistingOutput(t *testing.T) {
	root := t.TempDir()
	dataDir, keysDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := joltcrypto.LoadOrCreate(keysDir); err != nil {
		t.Fatal(err)
	}
	storage, err := db.Open(dataDir, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err := recovery.AcquireLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "node.tar.gz")
	if _, err := recovery.CreateSnapshot(context.Background(), dataDir, keysDir, output, make([]byte, 32)); !errors.Is(err, recovery.ErrInstanceActive) {
		t.Fatalf("active instance error=%v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.CreateSnapshot(context.Background(), dataDir, keysDir, output, make([]byte, 32)); err == nil {
		t.Fatal("existing output was overwritten")
	}
}

type ManifestAlias struct {
	NodeID string `json:"node_id"`
	Files  []any  `json:"files"`
}

func readArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	entries := map[string][]byte{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = content
	}
	return entries
}

func TestSnapshotRestoresConfigurationTrustJobsUploadsAndIdentity(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dataDir, keysDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	identity, err := joltcrypto.LoadOrCreate(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := db.Open(dataDir, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mountPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mount := entities.Mount{ID: "files", Name: "Files", LocalPath: mountPath, TargetType: "directory", Mode: "read_write", Enabled: true, Published: true}
	grant := entities.TransferPathGrant{ID: "send", PeerNodeID: "peer", MountID: "files", Path: ".", Direction: "send", Permissions: entities.GrantPermissions{Read: true}, Enabled: true}
	if err := s.ApplyConfiguration(ctx, "revision", []entities.Mount{mount}, []entities.TransferPathGrant{grant}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairingInvite(ctx, entities.PairingInvite{ID: "invite", Status: "pending", ExpiresAt: now.Add(time.Hour)}, "secret-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.ApprovePairingInvite(ctx, "invite", "secret-hash", entities.Peer{NodeID: "peer", State: "trusted", Fingerprint: "fingerprint"}, now); err != nil {
		t.Fatal(err)
	}
	job := entities.Job{ID: "job", MountID: "files", Type: "copy_local", State: "running", CreatedAt: now, BytesTotal: 4, BytesCompleted: 2}
	if _, _, err := s.CreateJobWithItemsHashed(ctx, job, []entities.JobItem{{RelativePath: "file", Size: 4, BytesCompleted: 2}}, "request", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUploadSession(ctx, entities.UploadSession{ID: "upload", MountID: "files", Destination: "upload.txt", Size: 4, Offset: 2, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecoverOperationalToken(ctx, "token-hash", "recovery", now); err != nil {
		t.Fatal(err)
	}
	s.Close()
	configuration := filepath.Join(root, "node.yaml")
	configBytes := []byte("version: 1\nnode_name: restored\n")
	if err := os.WriteFile(configuration, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "journal", ".tmp-unpublished"), []byte("do not include"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "unrelated-secret"), []byte("do not include"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "snapshot.tar.gz")
	if _, err := recovery.CreateSnapshot(ctx, dataDir, keysDir, archive, make([]byte, 32), configuration); err != nil {
		t.Fatal(err)
	}
	entries := readArchive(t, archive)
	if string(entries["node.yaml"]) != string(configBytes) {
		t.Fatal("configuration not preserved")
	}
	restored := t.TempDir()
	for name, data := range entries {
		if strings.Contains(name, ".tmp-") || strings.Contains(name, "unrelated-secret") {
			t.Fatal("excluded file included")
		}
		target := filepath.Join(restored, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	restoredIdentity, err := joltcrypto.LoadExisting(filepath.Join(restored, "keys"))
	if err != nil || restoredIdentity.NodeID != identity.NodeID || restoredIdentity.Fingerprint != identity.Fingerprint {
		t.Fatalf("identity: %+v %v", restoredIdentity, err)
	}
	restoredStore, err := db.Open(filepath.Join(restored, "data"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer restoredStore.Close()
	restoredGrant, err := restoredStore.GetTransferGrant(ctx, "send")
	if err != nil || !restoredGrant.Enabled {
		t.Fatalf("trust/grant: %+v %v", restoredGrant, err)
	}
	restoredJob, hash, found, err := restoredStore.FindJobByIdempotency(ctx, "request")
	if err != nil || !found || hash != "hash" || restoredJob.BytesCompleted != 2 {
		t.Fatal("job/idempotency not restored")
	}
	items, err := restoredStore.ListJobItems(ctx, "job")
	if err != nil || len(items) != 1 || items[0].BytesCompleted != 2 {
		t.Fatal("checkpoint not restored")
	}
	upload, err := restoredStore.GetUploadSession(ctx, "upload")
	if err != nil || upload.Offset != 2 {
		t.Fatal("upload not restored")
	}
	token, err := restoredStore.GetOperationalTokenState(ctx)
	if err != nil || token.ActiveHash != "token-hash" || !token.EnvTokenDisabled {
		t.Fatal("token not restored")
	}
	recovered, err := restoredStore.RecoverRunningJobs(ctx, now)
	if err != nil || len(recovered) != 1 || recovered[0].State != "waiting_validation" {
		t.Fatal("interrupted job resumed without validation")
	}
}

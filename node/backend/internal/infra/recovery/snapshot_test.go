package recovery_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/infra/recovery"
)

func TestNodeSnapshotContainsConsistentDatabaseKeysAndManifest(t *testing.T) {
	root := t.TempDir()
	dataDir, keysDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
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
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "desired.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(root, "backups", "node.tar.gz")
	manifest, err := recovery.CreateSnapshot(context.Background(), dataDir, keysDir, output)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Kind != "jolt_node" || manifest.DatabaseIntegrity != "ok" ||
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
	for _, expected := range []string{"manifest.json", "data/jolt.db", "data/desired.json", "keys/identity.json"} {
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
	if archived.NodeID != identity.NodeID || len(archived.Files) < 3 {
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
	storage, err := db.Open(filepath.Join(dataDir, "jolt.db"))
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
	if _, err := recovery.CreateSnapshot(context.Background(), dataDir, keysDir, output); !errors.Is(err, recovery.ErrInstanceActive) {
		t.Fatalf("active instance error=%v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.CreateSnapshot(context.Background(), dataDir, keysDir, output); err == nil {
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

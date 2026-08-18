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

	"github.com/jfxdev/jolt/control/internal/database"
	"github.com/jfxdev/jolt/control/internal/recovery"
	"github.com/jfxdev/jolt/control/internal/store"
)

var snapshotEncryptionKey = []byte("0123456789abcdef0123456789abcdef")

func TestControlSnapshotContainsConsistentDatabaseAndExcludesExternalKey(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	storage, err := store.Open(filepath.Join(dataDir, "control.db"), snapshotEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "preferences.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "backups", "control.tar.gz")
	manifest, err := recovery.CreateSnapshot(context.Background(), dataDir, output, snapshotEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Kind != "jolt_control_tower" || manifest.DatabaseIntegrity != "ok" ||
		manifest.ExternalKeyIncluded {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode=%o want=600", info.Mode().Perm())
	}
	entries := readControlArchive(t, output)
	for _, expected := range []string{"manifest.json", "data/control.db", "data/preferences.json"} {
		if _, exists := entries[expected]; !exists {
			t.Fatalf("archive is missing %s: %v", expected, entries)
		}
	}
	if _, exists := entries["data/control.db-wal"]; exists {
		t.Fatal("snapshot contains a transient SQLite WAL")
	}
	archivedDatabase := filepath.Join(root, "archived-control.db")
	if err := os.WriteFile(archivedDatabase, entries["data/control.db"], 0o600); err != nil {
		t.Fatal(err)
	}
	if plaintext, err := database.IsPlaintext(archivedDatabase); err != nil || plaintext {
		t.Fatalf("archived database is not encrypted: plaintext=%v err=%v", plaintext, err)
	}
	verified, err := database.Open(archivedDatabase, snapshotEncryptionKey, true)
	if err != nil {
		t.Fatalf("archived database cannot be unlocked: %v", err)
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	var archived struct {
		ExternalKeyIncluded bool  `json:"external_encryption_key_included"`
		Files               []any `json:"files"`
	}
	if err := json.Unmarshal(entries["manifest.json"], &archived); err != nil {
		t.Fatal(err)
	}
	if archived.ExternalKeyIncluded || len(archived.Files) < 2 {
		t.Fatalf("unexpected archived manifest: %+v", archived)
	}
}

func TestControlSnapshotRefusesActiveInstance(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	storage, err := store.Open(filepath.Join(dataDir, "control.db"), snapshotEncryptionKey)
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
	defer lock.Close()
	if _, err := recovery.CreateSnapshot(context.Background(), dataDir,
		filepath.Join(root, "control.tar.gz"), snapshotEncryptionKey); !errors.Is(err, recovery.ErrInstanceActive) {
		t.Fatalf("active instance error=%v", err)
	}
}

func readControlArchive(t *testing.T, path string) map[string][]byte {
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

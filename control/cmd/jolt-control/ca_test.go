package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/pki"
	"github.com/jfxdev/jolt/control/internal/recovery"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const testRootPassword = "a long passphrase for the root"

// controlTowerData is the data directory of a Control Tower that ran in managed
// mode once and was stopped.
func controlTowerData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("CONTROL_TOWER_DB_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("JOLT_ROOT_KEY_PASSWORD", testRootPassword)
	storage, err := store.Open(filepath.Join(dir, "control.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMetadata(context.Background(), "encryption_key_check", mustSeal(t, key)); err != nil {
		t.Fatal(err)
	}
	manager, err := pki.NewManager(storage, pki.Options{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = storage.Close()
	return dir
}

func mustSeal(t *testing.T, key []byte) string {
	t.Helper()
	sealed, err := security.Encrypt(key, security.EncryptionKeyCheck)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func rootSecret(t *testing.T, dir string) string {
	t.Helper()
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	storage, err := store.Open(filepath.Join(dir, "control.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	objects, _ := storage.ListPKIObjects(context.Background())
	for _, object := range objects {
		if object.Kind == store.PKIRoot && object.State == "active" {
			return object.Secret
		}
	}
	t.Fatal("no root")
	return ""
}

func intermediates(t *testing.T, dir string) int {
	t.Helper()
	key, _ := base64.StdEncoding.DecodeString(os.Getenv("CONTROL_TOWER_DB_ENCRYPTION_KEY"))
	storage, err := store.Open(filepath.Join(dir, "control.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	objects, _ := storage.ListPKIObjects(context.Background())
	total := 0
	for _, object := range objects {
		if object.Kind == store.PKIIntermediate && object.State != "revoked" {
			total++
		}
	}
	return total
}

func TestExportingTheRootNeedsAFreshFileAnAcknowledgementAndRemovesTheKey(t *testing.T) {
	dir := controlTowerData(t)
	out := filepath.Join(t.TempDir(), "root.json")
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out}); err == nil {
		t.Fatal("exported without the acknowledgement")
	}
	if err := runCA([]string{"export-root", "--data-dir", dir, "--confirm-remove-from-database"}); err == nil {
		t.Fatal("exported without a destination")
	}
	if rootSecret(t, dir) == "" {
		t.Fatal("a refused export removed the key")
	}
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", info, err)
	}
	if rootSecret(t, dir) != "" {
		t.Fatal("the key is still in the database")
	}
	// An earlier export is the only copy of the key: never overwritten.
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err == nil {
		t.Fatal("overwrote a file")
	}
}

func TestAPasswordThatIsMissingOrShortExportsNothing(t *testing.T) {
	dir := controlTowerData(t)
	out := filepath.Join(t.TempDir(), "root.json")
	t.Setenv("JOLT_ROOT_KEY_PASSWORD", "short")
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err == nil {
		t.Fatal("a short password was accepted")
	}
	t.Setenv("JOLT_ROOT_KEY_PASSWORD", "")
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err == nil {
		t.Fatal("no password was accepted")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a file was written without a valid password")
	}
	if rootSecret(t, dir) == "" {
		t.Fatal("the key was removed")
	}
}

func TestTheFileRenewsTheIntermediateAndTheKeyCanComeBack(t *testing.T) {
	dir := controlTowerData(t)
	out := filepath.Join(t.TempDir(), "root.json")
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err != nil {
		t.Fatal(err)
	}
	if err := runCA([]string{"renew-intermediate", "--data-dir", dir, "--root-file", out}); err != nil {
		t.Fatal(err)
	}
	if intermediates(t, dir) != 2 || rootSecret(t, dir) != "" {
		t.Fatalf("after renewing: %d intermediates, key stored %v", intermediates(t, dir), rootSecret(t, dir) != "")
	}
	t.Setenv("JOLT_ROOT_KEY_PASSWORD", "another passphrase entirely")
	if err := runCA([]string{"renew-intermediate", "--data-dir", dir, "--root-file", out}); err == nil {
		t.Fatal("a wrong password renewed the intermediate")
	}
	if err := runCA([]string{"import-root", "--data-dir", dir, "--in", out}); err == nil {
		t.Fatal("a wrong password imported the key")
	}
	t.Setenv("JOLT_ROOT_KEY_PASSWORD", testRootPassword)
	if err := runCA([]string{"import-root", "--data-dir", dir, "--in", out}); err != nil {
		t.Fatal(err)
	}
	if rootSecret(t, dir) == "" {
		t.Fatal("the key did not come back")
	}
}

func TestAKeyFileOthersCanReadIsNotUsed(t *testing.T) {
	dir := controlTowerData(t)
	out := filepath.Join(t.TempDir(), "root.json")
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o644); err != nil {
		t.Fatal(err)
	}
	err := runCA([]string{"renew-intermediate", "--data-dir", dir, "--root-file", out})
	if err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("got %v", err)
	}
	if intermediates(t, dir) != 1 {
		t.Fatal("an intermediate was issued from a file that was too open")
	}
}

func TestTheCommandsRefuseARunningControlTowerAndAWrongDatabaseKey(t *testing.T) {
	dir := controlTowerData(t)
	out := filepath.Join(t.TempDir(), "root.json")
	lock, err := recovery.AcquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"})
	_ = lock.Close()
	if err == nil || !strings.Contains(err.Error(), "stop the Control Tower") {
		t.Fatalf("running instance: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil || rootSecret(t, dir) == "" {
		t.Fatal("something changed while the Control Tower held the lock")
	}
	wrong := make([]byte, 32)
	t.Setenv("CONTROL_TOWER_DB_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(wrong))
	if err := runCA([]string{"status", "--data-dir", dir}); err == nil {
		t.Fatal("a wrong database key was accepted")
	}
}

func TestUnknownAndMissingCommandsExplainThemselves(t *testing.T) {
	if err := runCA(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("none: %v", err)
	}
	if err := runCA([]string{"destroy"}); err == nil || !strings.Contains(err.Error(), "unknown ca command") {
		t.Fatalf("unknown: %v", err)
	}
	if err := runCA([]string{"status", "extra"}); err == nil {
		t.Fatal("a stray argument was ignored")
	}
}

func TestAnExistingFileIsNeverReplacedAndTheKeyStaysWhereItWas(t *testing.T) {
	dir := controlTowerData(t)
	out := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(out, []byte("an earlier export"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCA([]string{"export-root", "--data-dir", dir, "--out", out, "--confirm-remove-from-database"}); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if got, _ := os.ReadFile(out); string(got) != "an earlier export" {
		t.Fatalf("the file was changed: %q", got)
	}
	if rootSecret(t, dir) == "" {
		t.Fatal("the key left the database although no file was written")
	}
}

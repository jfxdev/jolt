package crypto

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("identity changed: %#v != %#v", first, second)
	}
	info, err := os.Stat(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity mode = %o, want 600", got)
	}
}

func TestIdentityRejectsPermissivePrivateFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("expected unsafe permission error")
	}
}

func TestIdentityRotationPreservesNodeIDAndRequiresRestart(t *testing.T) {
	dir := t.TempDir()
	current, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	next, err := RotateIdentity(dir, current, current.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if next.NodeID != current.NodeID || next.Fingerprint == current.Fingerprint ||
		next.PublicKey == current.PublicKey || next.Epoch != current.Epoch+1 {
		t.Fatalf("current=%+v next=%+v", current, next)
	}
	handovers, err := LoadIdentityHandovers(dir)
	if err != nil || len(handovers) != 1 {
		t.Fatalf("handovers=%+v err=%v", handovers, err)
	}
	handover := handovers[0]
	if handover.NodeID != current.NodeID || handover.PreviousEpoch != current.Epoch ||
		handover.NextEpoch != next.Epoch || handover.PreviousFingerprint != current.Fingerprint ||
		handover.NextFingerprint != next.Fingerprint {
		t.Fatalf("handover does not continue identity: %+v", handover)
	}
	if err := VerifyIdentityHandover(handover, time.Now().UTC()); err != nil {
		t.Fatalf("valid handover rejected: %v", err)
	}
	tampered := handover
	tampered.NextFingerprint = current.Fingerprint
	if err := VerifyIdentityHandover(tampered, time.Now().UTC()); err == nil {
		t.Fatal("tampered handover was accepted")
	}
	persisted, err := LoadOrCreate(dir)
	if err != nil || persisted != next {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	if _, err := RotateIdentity(dir, current, current.Fingerprint); err != ErrIdentityRestart {
		t.Fatalf("second rotation error=%v, want ErrIdentityRestart", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.previous-"+stringsNoColons(current.Fingerprint)+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityRotationRequiresExactFingerprintConfirmation(t *testing.T) {
	dir := t.TempDir()
	current, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RotateIdentity(dir, current, "WRONG"); err != ErrIdentityConfirmation {
		t.Fatalf("error=%v, want ErrIdentityConfirmation", err)
	}
	persisted, err := LoadOrCreate(dir)
	if err != nil || persisted != current {
		t.Fatalf("identity changed after rejected rotation: persisted=%+v err=%v", persisted, err)
	}
}

func TestCertificateMaterialIsRegeneratedAfterIdentityRotationAndRestart(t *testing.T) {
	dir := t.TempDir()
	current, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := LoadOrCreateCertificateManager(dir, current, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldCertificateFingerprint := manager.Snapshot().Current.IdentityFingerprint
	next, err := RotateIdentity(dir, current, current.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadOrCreate(dir)
	if err != nil || restarted != next {
		t.Fatalf("restarted=%+v next=%+v err=%v", restarted, next, err)
	}
	nextManager, err := LoadOrCreateCertificateManager(dir, restarted, nil)
	if err != nil {
		t.Fatal(err)
	}
	if nextManager.Snapshot().Current.IdentityFingerprint != next.Fingerprint ||
		nextManager.Snapshot().Current.IdentityFingerprint == oldCertificateFingerprint {
		t.Fatalf("certificate was not regenerated: %+v", nextManager.Snapshot().Current)
	}
	archive := filepath.Join(dir, "mtls.identity-"+stringsNoColons(current.Fingerprint))
	if _, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	}
}

package crypto

import (
	"context"
	"crypto/tls"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

type staticPeers []entities.Peer

func (p staticPeers) ListPeers(context.Context) ([]entities.Peer, error) {
	return []entities.Peer(p), nil
}

func certificateTestIdentity(t *testing.T, dir string) entities.Identity {
	t.Helper()
	identity, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestCertificateManagersAuthenticateExactTrustedPeers(t *testing.T) {
	dirA, dirB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	identityA := certificateTestIdentity(t, dirA)
	identityB := certificateTestIdentity(t, dirB)
	managerA, err := LoadOrCreateCertificateManager(dirA, identityA, staticPeers{{
		NodeID: identityB.NodeID, Fingerprint: identityB.Fingerprint, State: "trusted",
	}})
	if err != nil {
		t.Fatal(err)
	}
	managerB, err := LoadOrCreateCertificateManager(dirB, identityB, staticPeers{{
		NodeID: identityA.NodeID, Fingerprint: identityA.Fingerprint, State: "trusted",
	}})
	if err != nil {
		t.Fatal(err)
	}

	serverConnection, clientConnection := net.Pipe()
	server := tls.Server(serverConnection, managerA.TLSConfig())
	client := tls.Client(clientConnection, managerB.ClientTLSConfig(identityA.NodeID, identityA.Fingerprint))
	defer server.Close()
	defer client.Close()

	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

func TestCertificateManagerRejectsUntrustedPeer(t *testing.T) {
	dirA, dirB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	identityA := certificateTestIdentity(t, dirA)
	identityB := certificateTestIdentity(t, dirB)
	managerA, err := LoadOrCreateCertificateManager(dirA, identityA, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	managerB, err := LoadOrCreateCertificateManager(dirB, identityB, staticPeers{{
		NodeID: identityA.NodeID, Fingerprint: identityA.Fingerprint, State: "trusted",
	}})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := managerB.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := managerA.VerifyPeerCertificate(certificate.Certificate, "", ""); err == nil {
		t.Fatal("expected the verifier to reject an untrusted client identity")
	}
}

func TestCertificateManagerAllowsSignedIdentityOverlapUntilPromotion(t *testing.T) {
	dirPeer, dirVerifier := filepath.Join(t.TempDir(), "peer"), filepath.Join(t.TempDir(), "verifier")
	previous := certificateTestIdentity(t, dirPeer)
	verifierIdentity := certificateTestIdentity(t, dirVerifier)
	previousManager, err := LoadOrCreateCertificateManager(dirPeer, previous, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	previousCertificate, err := previousManager.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := RotateIdentity(dirPeer, previous, previous.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	nextManager, err := LoadOrCreateCertificateManager(dirPeer, next, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	nextCertificate, err := nextManager.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	overlapVerifier, err := LoadOrCreateCertificateManager(dirVerifier, verifierIdentity, staticPeers{{
		NodeID: previous.NodeID, Fingerprint: next.Fingerprint,
		PreviousFingerprint: previous.Fingerprint, IdentityEpoch: next.Epoch, State: "unknown",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, certificate := range map[string]tls.Certificate{
		"previous": *previousCertificate, "next": *nextCertificate,
	} {
		if err := overlapVerifier.VerifyPeerCertificate(certificate.Certificate, "", ""); err != nil {
			t.Fatalf("%s identity rejected during overlap: %v", name, err)
		}
	}
	promotedVerifier, err := LoadOrCreateCertificateManager(dirVerifier, verifierIdentity, staticPeers{{
		NodeID: previous.NodeID, Fingerprint: next.Fingerprint, IdentityEpoch: next.Epoch, State: "online",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := promotedVerifier.VerifyPeerCertificate(previousCertificate.Certificate, "", ""); err == nil {
		t.Fatal("previous identity remained trusted after promotion")
	}
	if err := promotedVerifier.VerifyPeerCertificate(nextCertificate.Certificate, "", ""); err != nil {
		t.Fatalf("next identity rejected after promotion: %v", err)
	}
}

func TestCertificateRotationPromotionAndRevocationPersist(t *testing.T) {
	dir := t.TempDir()
	identity := certificateTestIdentity(t, dir)
	manager, err := LoadOrCreateCertificateManager(dir, identity, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	original := manager.Snapshot().Current
	next, err := manager.PrepareRotation(48*time.Hour, "cor-prepare")
	if err != nil {
		t.Fatal(err)
	}
	if next.Serial == original.Serial {
		t.Fatal("rotation reused the current certificate")
	}
	promoted, err := manager.Promote(2*time.Hour, "cor-promote")
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Serial != next.Serial {
		t.Fatalf("promoted serial=%s want=%s", promoted.Serial, next.Serial)
	}
	if err := manager.Revoke(original.Serial, "retired", "cor-revoke"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadOrCreateCertificateManager(dir, identity, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	state := reloaded.Snapshot()
	if state.Current.Serial != next.Serial || state.Previous.RevokedAt == nil {
		t.Fatalf("unexpected persisted state: %#v", state)
	}
	if len(state.Events) != 4 {
		t.Fatalf("event count=%d want=4", len(state.Events))
	}
}

func TestCertificateRolloutIsValidatedAcknowledgedAndPersisted(t *testing.T) {
	dirA, dirB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	identityA := certificateTestIdentity(t, dirA)
	identityB := certificateTestIdentity(t, dirB)
	managerA, err := LoadOrCreateCertificateManager(dirA, identityA, staticPeers{{
		NodeID: identityB.NodeID, Fingerprint: identityB.Fingerprint, State: "online",
	}})
	if err != nil {
		t.Fatal(err)
	}
	managerB, err := LoadOrCreateCertificateManager(dirB, identityB, staticPeers{{
		NodeID: identityA.NodeID, Fingerprint: identityA.Fingerprint, State: "trusted",
	}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := managerA.PrepareRotation(48*time.Hour, "cor-prepare")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := managerA.NextRolloutEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	acceptance, err := managerB.AcceptPeerRollout(identityA.NodeID, envelope, "cor-accept")
	if err != nil {
		t.Fatal(err)
	}
	if acceptance.Serial != next.Serial || acceptance.NodeID != identityA.NodeID {
		t.Fatalf("unexpected acceptance: %+v", acceptance)
	}
	rollout, err := managerA.RecordRolloutDelivery(next.Serial, identityB.NodeID, "", "cor-ack")
	if err != nil {
		t.Fatal(err)
	}
	if rollout.Peers[identityB.NodeID].Status != "acknowledged" ||
		rollout.Peers[identityB.NodeID].AcknowledgedAt == nil {
		t.Fatalf("unexpected rollout: %+v", rollout)
	}

	reloadedA, err := LoadOrCreateCertificateManager(dirA, identityA, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	reloadedB, err := LoadOrCreateCertificateManager(dirB, identityB, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	if reloadedA.Snapshot().Rollouts[next.Serial].Peers[identityB.NodeID].Status != "acknowledged" {
		t.Fatal("source acknowledgement was not persisted")
	}
	key := identityA.NodeID + ":" + next.Serial
	if reloadedB.Snapshot().AcceptedPeerCertificates[key].CertificateSHA256 != next.CertificateSHA256 {
		t.Fatal("peer certificate acceptance was not persisted")
	}
}

func TestCertificateRolloutRejectsTamperingAndUntrustedIdentity(t *testing.T) {
	dirA, dirB := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	identityA := certificateTestIdentity(t, dirA)
	identityB := certificateTestIdentity(t, dirB)
	managerA, err := LoadOrCreateCertificateManager(dirA, identityA, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	managerB, err := LoadOrCreateCertificateManager(dirB, identityB, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managerA.PrepareRotation(48*time.Hour, "cor-prepare"); err != nil {
		t.Fatal(err)
	}
	envelope, err := managerA.NextRolloutEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	envelope.Certificate.CertificateSHA256 = "TAMPERED"
	if _, err := managerB.AcceptPeerRollout(identityA.NodeID, envelope, "cor-reject"); err == nil {
		t.Fatal("tampered rollout was accepted")
	}
}

func TestCertificatePromotionCanRollbackDuringGraceWindow(t *testing.T) {
	dir := t.TempDir()
	identity := certificateTestIdentity(t, dir)
	manager, err := LoadOrCreateCertificateManager(dir, identity, staticPeers{})
	if err != nil {
		t.Fatal(err)
	}
	original := manager.Snapshot().Current
	next, err := manager.PrepareRotation(48*time.Hour, "cor-prepare")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Promote(time.Hour, "cor-promote"); err != nil {
		t.Fatal(err)
	}
	restored, err := manager.Rollback("cor-rollback")
	if err != nil {
		t.Fatal(err)
	}
	state := manager.Snapshot()
	if restored.Serial != original.Serial || state.Current.Serial != original.Serial ||
		state.Next.Serial != next.Serial || state.Previous != nil {
		t.Fatalf("unexpected rollback state: %#v", state)
	}
}

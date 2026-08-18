package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

var (
	ErrCertificateUnavailable = errors.New("mTLS certificate unavailable")
	ErrCertificateInvalid     = errors.New("invalid mTLS certificate")
	ErrCertificateRevoked     = errors.New("mTLS certificate revoked")
	ErrRotationPending        = errors.New("an mTLS certificate rotation is already pending")
	ErrNoRotationPending      = errors.New("no mTLS certificate rotation is pending")
	ErrRollbackUnavailable    = errors.New("mTLS certificate rollback is unavailable")
)

var identityPublicKeyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

type PeerSource interface {
	ListPeers(context.Context) ([]entities.Peer, error)
}

type CertificateMetadata struct {
	KeyID               string     `json:"key_id"`
	Serial              string     `json:"serial"`
	CertificateSHA256   string     `json:"certificate_sha256"`
	IdentityFingerprint string     `json:"identity_fingerprint"`
	Issuer              string     `json:"issuer"`
	Subject             string     `json:"subject"`
	State               string     `json:"state"`
	NotBefore           time.Time  `json:"not_before"`
	NotAfter            time.Time  `json:"not_after"`
	CreatedAt           time.Time  `json:"created_at"`
	PromotedAt          *time.Time `json:"promoted_at,omitempty"`
	GraceUntil          *time.Time `json:"grace_until,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
}

type CertificateRevocation struct {
	Serial        string    `json:"serial"`
	Reason        string    `json:"reason"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	RevokedAt     time.Time `json:"revoked_at"`
}

type CertificateEvent struct {
	Action        string    `json:"action"`
	Serial        string    `json:"serial"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type CertificateRolloutPeer struct {
	NodeID         string     `json:"node_id"`
	Status         string     `json:"status"`
	LastError      string     `json:"last_error,omitempty"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

type CertificateRollout struct {
	Serial    string                            `json:"serial"`
	StartedAt time.Time                         `json:"started_at"`
	Peers     map[string]CertificateRolloutPeer `json:"peers"`
}

type PeerCertificateAcceptance struct {
	NodeID              string    `json:"node_id"`
	Serial              string    `json:"serial"`
	CertificateSHA256   string    `json:"certificate_sha256"`
	IdentityFingerprint string    `json:"identity_fingerprint"`
	AcceptedAt          time.Time `json:"accepted_at"`
	CorrelationID       string    `json:"correlation_id,omitempty"`
}

type CertificateRolloutEnvelope struct {
	NodeID         string              `json:"node_id"`
	Certificate    CertificateMetadata `json:"certificate"`
	CertificatePEM string              `json:"certificate_pem"`
}

type CertificateState struct {
	Version                  int                                  `json:"version"`
	Current                  *CertificateMetadata                 `json:"current,omitempty"`
	Next                     *CertificateMetadata                 `json:"next,omitempty"`
	Previous                 *CertificateMetadata                 `json:"previous,omitempty"`
	Revocations              map[string]CertificateRevocation     `json:"revocations"`
	Rollouts                 map[string]CertificateRollout        `json:"rollouts"`
	AcceptedPeerCertificates map[string]PeerCertificateAcceptance `json:"accepted_peer_certificates"`
	Events                   []CertificateEvent                   `json:"events"`
}

type CertificateManager struct {
	mu              sync.RWMutex
	dir             string
	identity        entities.Identity
	identityPrivate ed25519.PrivateKey
	peers           PeerSource
	now             func() time.Time
	state           CertificateState
}

func LoadOrCreateCertificateManager(keysDir string, identity entities.Identity, peers PeerSource) (*CertificateManager, error) {
	stored, privateKey, err := loadPrivateIdentity(keysDir)
	if err != nil {
		return nil, fmt.Errorf("load identity signer: %w", err)
	}
	publicIdentity, err := publicIdentity(stored)
	if err != nil {
		return nil, err
	}
	if publicIdentity != identity {
		return nil, errors.New("stored identity does not match the active node identity")
	}
	if err := archiveMTLSForIdentityChange(keysDir, identity); err != nil {
		return nil, err
	}
	dir := filepath.Join(keysDir, "mtls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create mTLS keys directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure mTLS keys directory: %w", err)
	}
	manager := &CertificateManager{
		dir: dir, identity: identity, identityPrivate: privateKey, peers: peers,
		now: func() time.Time { return time.Now().UTC() },
		state: CertificateState{
			Version: 1, Revocations: map[string]CertificateRevocation{},
			Rollouts:                 map[string]CertificateRollout{},
			AcceptedPeerCertificates: map[string]PeerCertificateAcceptance{},
		},
	}
	if err := manager.loadState(); err != nil {
		return nil, err
	}
	if manager.state.Current == nil {
		metadata, err := manager.generateCertificate(365 * 24 * time.Hour)
		if err != nil {
			return nil, err
		}
		now := manager.now()
		metadata.State = "active"
		metadata.PromotedAt = &now
		manager.state.Current = &metadata
		manager.recordEvent("created", metadata.Serial, "")
		if err := manager.persistState(); err != nil {
			return nil, err
		}
	}
	if _, err := manager.certificateFor(manager.state.Current); err != nil {
		return nil, fmt.Errorf("load active mTLS certificate: %w", err)
	}
	return manager, nil
}

func archiveMTLSForIdentityChange(keysDir string, identity entities.Identity) error {
	dir := filepath.Join(keysDir, "mtls")
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state CertificateState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("decode mTLS state before identity migration: %w", err)
	}
	if state.Current == nil || state.Current.IdentityFingerprint == identity.Fingerprint {
		return nil
	}
	archive := filepath.Join(keysDir, "mtls.identity-"+stringsNoColons(state.Current.IdentityFingerprint))
	if _, err := os.Stat(archive); err == nil {
		return errors.New("mTLS archive for the previous identity already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(dir, archive); err != nil {
		return fmt.Errorf("archive previous identity mTLS material: %w", err)
	}
	return nil
}

func (m *CertificateManager) Snapshot() CertificateState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	encoded, _ := json.Marshal(m.state)
	var snapshot CertificateState
	_ = json.Unmarshal(encoded, &snapshot)
	now := m.now()
	for _, metadata := range []*CertificateMetadata{snapshot.Current, snapshot.Next, snapshot.Previous} {
		if metadata != nil && metadata.RevokedAt == nil && now.After(metadata.NotAfter) {
			metadata.State = "expired"
		}
	}
	if snapshot.Previous != nil && snapshot.Previous.RevokedAt == nil &&
		snapshot.Previous.GraceUntil != nil && now.After(*snapshot.Previous.GraceUntil) {
		snapshot.Previous.State = "expired"
	}
	return snapshot
}

func (m *CertificateManager) PrepareRotation(validFor time.Duration, correlationID string) (CertificateMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Next != nil {
		return CertificateMetadata{}, ErrRotationPending
	}
	if validFor <= 0 {
		validFor = 365 * 24 * time.Hour
	}
	if validFor < 24*time.Hour || validFor > 5*365*24*time.Hour {
		return CertificateMetadata{}, fmt.Errorf("%w: validity must be between 1 day and 5 years", ErrCertificateInvalid)
	}
	rolloutPeers := map[string]CertificateRolloutPeer{}
	if m.peers != nil {
		peers, err := m.peers.ListPeers(context.Background())
		if err != nil {
			return CertificateMetadata{}, fmt.Errorf("load peers for certificate rollout: %w", err)
		}
		for _, peer := range peers {
			if trustedPeerState(peer.State) {
				rolloutPeers[peer.NodeID] = CertificateRolloutPeer{
					NodeID: peer.NodeID, Status: "pending",
				}
			}
		}
	}
	metadata, err := m.generateCertificate(validFor)
	if err != nil {
		return CertificateMetadata{}, err
	}
	m.state.Next = &metadata
	rollout := CertificateRollout{
		Serial: metadata.Serial, StartedAt: m.now(),
		Peers: rolloutPeers,
	}
	m.state.Rollouts[metadata.Serial] = rollout
	eventCount := len(m.state.Events)
	m.recordEvent("prepared", metadata.Serial, correlationID)
	if err := m.persistState(); err != nil {
		m.state.Next = nil
		delete(m.state.Rollouts, metadata.Serial)
		m.state.Events = m.state.Events[:eventCount]
		return CertificateMetadata{}, err
	}
	return metadata, nil
}

func (m *CertificateManager) NextRolloutEnvelope() (CertificateRolloutEnvelope, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state.Next == nil {
		return CertificateRolloutEnvelope{}, ErrNoRotationPending
	}
	certPath, _ := m.artifactPaths(m.state.Next.Serial)
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return CertificateRolloutEnvelope{}, fmt.Errorf("read next public certificate: %w", err)
	}
	return CertificateRolloutEnvelope{
		NodeID: m.identity.NodeID, Certificate: *m.state.Next,
		CertificatePEM: string(certificatePEM),
	}, nil
}

func (m *CertificateManager) AcceptPeerRollout(expectedPeerNodeID string,
	envelope CertificateRolloutEnvelope, correlationID string) (PeerCertificateAcceptance, error) {
	expectedPeerNodeID = strings.TrimSpace(expectedPeerNodeID)
	if expectedPeerNodeID == "" || envelope.NodeID != expectedPeerNodeID ||
		envelope.Certificate.Serial == "" || envelope.Certificate.State != "next" ||
		envelope.CertificatePEM == "" {
		return PeerCertificateAcceptance{}, fmt.Errorf("%w: invalid certificate rollout envelope", ErrCertificateInvalid)
	}
	block, rest := pem.Decode([]byte(envelope.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return PeerCertificateAcceptance{}, fmt.Errorf("%w: rollout must contain exactly one PEM certificate", ErrCertificateInvalid)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return PeerCertificateAcceptance{}, fmt.Errorf("%w: %v", ErrCertificateInvalid, err)
	}
	if certificate.Subject.CommonName != expectedPeerNodeID ||
		strings.ToLower(certificate.SerialNumber.Text(16)) != strings.ToLower(envelope.Certificate.Serial) {
		return PeerCertificateAcceptance{}, fmt.Errorf("%w: rollout certificate metadata does not match", ErrCertificateInvalid)
	}
	sum := sha256.Sum256(block.Bytes)
	certificateSHA256 := strings.ToUpper(hex.EncodeToString(sum[:]))
	if certificateSHA256 != envelope.Certificate.CertificateSHA256 {
		return PeerCertificateAcceptance{}, fmt.Errorf("%w: rollout certificate digest does not match", ErrCertificateInvalid)
	}
	if err := m.verifyPeerCertificateFingerprints([][]byte{block.Bytes}, "", nil); err != nil {
		return PeerCertificateAcceptance{}, err
	}
	_, identityFingerprint, err := certificateIdentity(certificate)
	if err != nil || identityFingerprint != envelope.Certificate.IdentityFingerprint {
		return PeerCertificateAcceptance{}, fmt.Errorf("%w: rollout identity does not match", ErrCertificateInvalid)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	acceptance := PeerCertificateAcceptance{
		NodeID: expectedPeerNodeID, Serial: envelope.Certificate.Serial,
		CertificateSHA256:   certificateSHA256,
		IdentityFingerprint: identityFingerprint,
		AcceptedAt:          m.now(), CorrelationID: correlationID,
	}
	key := expectedPeerNodeID + ":" + strings.ToLower(envelope.Certificate.Serial)
	previous, existed := m.state.AcceptedPeerCertificates[key]
	m.state.AcceptedPeerCertificates[key] = acceptance
	eventCount := len(m.state.Events)
	m.recordEvent("peer_rollout_accepted", envelope.Certificate.Serial, correlationID)
	if err := m.persistState(); err != nil {
		if existed {
			m.state.AcceptedPeerCertificates[key] = previous
		} else {
			delete(m.state.AcceptedPeerCertificates, key)
		}
		m.state.Events = m.state.Events[:eventCount]
		return PeerCertificateAcceptance{}, err
	}
	return acceptance, nil
}

func (m *CertificateManager) RecordRolloutDelivery(serial, peerNodeID, deliveryError,
	correlationID string) (CertificateRollout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	serial, peerNodeID = strings.ToLower(strings.TrimSpace(serial)), strings.TrimSpace(peerNodeID)
	rollout, exists := m.state.Rollouts[serial]
	if !exists {
		return CertificateRollout{}, ErrNoRotationPending
	}
	peer, exists := rollout.Peers[peerNodeID]
	if !exists {
		return CertificateRollout{}, fmt.Errorf("%w: peer is not part of this rollout", ErrCertificateInvalid)
	}
	previousPeer := peer
	now := m.now()
	peer.LastAttemptAt = &now
	peer.LastError = strings.TrimSpace(deliveryError)
	if peer.LastError == "" {
		peer.Status, peer.AcknowledgedAt = "acknowledged", &now
	} else {
		peer.Status, peer.AcknowledgedAt = "failed", nil
	}
	rollout.Peers[peerNodeID] = peer
	m.state.Rollouts[serial] = rollout
	eventCount := len(m.state.Events)
	action := "rollout_acknowledged"
	if deliveryError != "" {
		action = "rollout_failed"
	}
	m.recordEvent(action, serial, correlationID)
	if err := m.persistState(); err != nil {
		rollout.Peers[peerNodeID] = previousPeer
		m.state.Rollouts[serial] = rollout
		m.state.Events = m.state.Events[:eventCount]
		return CertificateRollout{}, err
	}
	return rollout, nil
}

func (m *CertificateManager) Promote(gracePeriod time.Duration, correlationID string) (CertificateMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Next == nil {
		return CertificateMetadata{}, ErrNoRotationPending
	}
	if gracePeriod < 0 || gracePeriod > 30*24*time.Hour {
		return CertificateMetadata{}, fmt.Errorf("%w: grace period must be between 0 and 30 days", ErrCertificateInvalid)
	}
	oldCurrent, oldNext, oldPrevious := m.state.Current, m.state.Next, m.state.Previous
	eventCount := len(m.state.Events)
	now := m.now()
	if m.state.Current != nil {
		previous := *m.state.Current
		previous.State = "previous"
		graceUntil := now.Add(gracePeriod)
		previous.GraceUntil = &graceUntil
		m.state.Previous = &previous
	}
	current := *m.state.Next
	current.State = "active"
	current.PromotedAt = &now
	m.state.Current, m.state.Next = &current, nil
	m.recordEvent("promoted", current.Serial, correlationID)
	if err := m.persistState(); err != nil {
		m.state.Current, m.state.Next, m.state.Previous = oldCurrent, oldNext, oldPrevious
		m.state.Events = m.state.Events[:eventCount]
		return CertificateMetadata{}, err
	}
	return current, nil
}

func (m *CertificateManager) Rollback(correlationID string) (CertificateMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Previous == nil || m.state.Previous.GraceUntil == nil ||
		!m.now().Before(*m.state.Previous.GraceUntil) || m.state.Previous.RevokedAt != nil {
		return CertificateMetadata{}, ErrRollbackUnavailable
	}
	oldCurrent, oldNext, oldPrevious := m.state.Current, m.state.Next, m.state.Previous
	eventCount := len(m.state.Events)
	now := m.now()
	restored := *m.state.Previous
	restored.State, restored.GraceUntil, restored.PromotedAt = "active", nil, &now
	if m.state.Current != nil && m.state.Current.RevokedAt == nil {
		displaced := *m.state.Current
		displaced.State, displaced.PromotedAt, displaced.GraceUntil = "next", nil, nil
		m.state.Next = &displaced
	}
	m.state.Current, m.state.Previous = &restored, nil
	m.recordEvent("rolled_back", restored.Serial, correlationID)
	if err := m.persistState(); err != nil {
		m.state.Current, m.state.Next, m.state.Previous = oldCurrent, oldNext, oldPrevious
		m.state.Events = m.state.Events[:eventCount]
		return CertificateMetadata{}, err
	}
	return restored, nil
}

func (m *CertificateManager) Revoke(serial, reason, correlationID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	serial = strings.ToLower(strings.TrimSpace(serial))
	if serial == "" {
		return fmt.Errorf("%w: serial is required", ErrCertificateInvalid)
	}
	if _, exists := m.state.Revocations[serial]; exists {
		return nil
	}
	eventCount := len(m.state.Events)
	now := m.now()
	revocation := CertificateRevocation{
		Serial: serial, Reason: strings.TrimSpace(reason), CorrelationID: correlationID, RevokedAt: now,
	}
	m.state.Revocations[serial] = revocation
	previousStates := map[*CertificateMetadata]struct {
		state     string
		revokedAt *time.Time
	}{}
	for _, metadata := range []*CertificateMetadata{m.state.Current, m.state.Next, m.state.Previous} {
		if metadata != nil && metadata.Serial == serial {
			previousStates[metadata] = struct {
				state     string
				revokedAt *time.Time
			}{metadata.State, metadata.RevokedAt}
			metadata.RevokedAt = &now
			metadata.State = "revoked"
		}
	}
	m.recordEvent("revoked", serial, correlationID)
	if err := m.persistState(); err != nil {
		delete(m.state.Revocations, serial)
		for metadata, previous := range previousStates {
			metadata.State, metadata.RevokedAt = previous.state, previous.revokedAt
		}
		m.state.Events = m.state.Events[:eventCount]
		return err
	}
	return nil
}

func (m *CertificateManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state.Current == nil {
		return nil, ErrCertificateUnavailable
	}
	if _, revoked := m.state.Revocations[m.state.Current.Serial]; revoked {
		return nil, ErrCertificateRevoked
	}
	now := m.now()
	if now.Before(m.state.Current.NotBefore) || now.After(m.state.Current.NotAfter) {
		return nil, fmt.Errorf("%w: active certificate is outside its validity window", ErrCertificateInvalid)
	}
	certificate, err := m.certificateFor(m.state.Current)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

func (m *CertificateManager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: m.GetCertificate,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return m.VerifyPeerCertificate(rawCerts, "", "")
		},
	}
}

func (m *CertificateManager) ClientTLSConfig(expectedNodeID string, expectedFingerprints ...string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Verification is identity-bound below, not PKI/hostname based.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return m.GetCertificate(nil)
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return m.verifyPeerCertificateFingerprints(rawCerts, expectedNodeID, expectedFingerprints)
		},
	}
}

func (m *CertificateManager) VerifyPeerCertificate(rawCerts [][]byte, expectedNodeID, expectedFingerprint string) error {
	return m.verifyPeerCertificateFingerprints(rawCerts, expectedNodeID, []string{expectedFingerprint})
}

func (m *CertificateManager) verifyPeerCertificateFingerprints(rawCerts [][]byte, expectedNodeID string,
	expectedFingerprints []string) error {
	if len(rawCerts) != 1 {
		return fmt.Errorf("%w: exactly one leaf certificate is required", ErrCertificateInvalid)
	}
	certificate, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateInvalid, err)
	}
	now := m.now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return fmt.Errorf("%w: certificate is outside its validity window", ErrCertificateInvalid)
	}
	serial := strings.ToLower(certificate.SerialNumber.Text(16))
	m.mu.RLock()
	_, revoked := m.state.Revocations[serial]
	m.mu.RUnlock()
	if revoked {
		return ErrCertificateRevoked
	}
	identityPublic, fingerprint, err := certificateIdentity(certificate)
	if err != nil {
		return err
	}
	if !ed25519.Verify(identityPublic, certificate.RawTBSCertificate, certificate.Signature) {
		return fmt.Errorf("%w: certificate is not signed by its declared node identity", ErrCertificateInvalid)
	}
	nodeID := certificate.Subject.CommonName
	if expectedNodeID != "" {
		matched := false
		for _, expectedFingerprint := range expectedFingerprints {
			if expectedFingerprint != "" && fingerprint == expectedFingerprint {
				matched = true
				break
			}
		}
		if nodeID != expectedNodeID || !matched {
			return fmt.Errorf("%w: peer identity does not match the expected trusted peer", ErrCertificateInvalid)
		}
		return nil
	}
	if m.peers == nil {
		return fmt.Errorf("%w: trusted peer registry is unavailable", ErrCertificateInvalid)
	}
	peers, err := m.peers.ListPeers(context.Background())
	if err != nil {
		return fmt.Errorf("load trusted peers: %w", err)
	}
	for _, peer := range peers {
		if trustedPeerState(peer.State) && peer.NodeID == nodeID &&
			(peer.Fingerprint == fingerprint || peer.PreviousFingerprint == fingerprint) {
			return nil
		}
	}
	return fmt.Errorf("%w: certificate does not belong to an exact trusted peer", ErrCertificateInvalid)
}

func trustedPeerState(state string) bool {
	switch state {
	case "trusted", "unknown", "online", "offline", "degraded":
		return true
	default:
		return false
	}
}

func (m *CertificateManager) generateCertificate(validFor time.Duration) (CertificateMetadata, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CertificateMetadata{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return CertificateMetadata{}, err
	}
	now := m.now()
	identityDER, err := asn1.Marshal([]byte(m.identityPrivate.Public().(ed25519.PublicKey)))
	if err != nil {
		return CertificateMetadata{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: m.identity.NodeID, Organization: []string{"jolt node"}},
		Issuer:       pkix.Name{CommonName: m.identity.NodeID, Organization: []string{"jolt identity"}},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: identityPublicKeyOID, Critical: true, Value: identityDER}},
	}
	parent := &x509.Certificate{Subject: template.Issuer, PublicKey: m.identityPrivate.Public()}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, m.identityPrivate)
	if err != nil {
		return CertificateMetadata{}, err
	}
	serialText := strings.ToLower(serial.Text(16))
	certPath, keyPath := m.artifactPaths(serialText)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return CertificateMetadata{}, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := atomicWrite(certPath, certificatePEM, 0o600); err != nil {
		return CertificateMetadata{}, err
	}
	if err := atomicWrite(keyPath, privatePEM, 0o600); err != nil {
		return CertificateMetadata{}, err
	}
	sum := sha256.Sum256(der)
	keySum := sha256.Sum256(publicKey)
	return CertificateMetadata{
		KeyID:  strings.ToUpper(hex.EncodeToString(keySum[:8])),
		Serial: serialText, CertificateSHA256: strings.ToUpper(hex.EncodeToString(sum[:])),
		IdentityFingerprint: m.identity.Fingerprint,
		Issuer:              template.Issuer.String(), Subject: template.Subject.String(), State: "next",
		NotBefore: template.NotBefore, NotAfter: template.NotAfter, CreatedAt: now,
	}, nil
}

func (m *CertificateManager) certificateFor(metadata *CertificateMetadata) (tls.Certificate, error) {
	if metadata == nil {
		return tls.Certificate{}, ErrCertificateUnavailable
	}
	certPath, keyPath := m.artifactPaths(metadata.Serial)
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(certificate.Certificate) != 1 {
		return tls.Certificate{}, fmt.Errorf("%w: certificate chain must contain one leaf", ErrCertificateInvalid)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: %v", ErrCertificateInvalid, err)
	}
	identityPublic, fingerprint, err := certificateIdentity(leaf)
	if err != nil {
		return tls.Certificate{}, err
	}
	if leaf.Subject.CommonName != m.identity.NodeID || fingerprint != m.identity.Fingerprint ||
		!ed25519.Verify(identityPublic, leaf.RawTBSCertificate, leaf.Signature) {
		return tls.Certificate{}, fmt.Errorf("%w: certificate is not bound to the active node identity", ErrCertificateInvalid)
	}
	sum := sha256.Sum256(certificate.Certificate[0])
	if strings.ToUpper(hex.EncodeToString(sum[:])) != metadata.CertificateSHA256 {
		return tls.Certificate{}, fmt.Errorf("%w: certificate fingerprint does not match persisted metadata", ErrCertificateInvalid)
	}
	return certificate, nil
}

func certificateIdentity(certificate *x509.Certificate) (ed25519.PublicKey, string, error) {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(identityPublicKeyOID) {
			var raw []byte
			if _, err := asn1.Unmarshal(extension.Value, &raw); err != nil || len(raw) != ed25519.PublicKeySize {
				return nil, "", fmt.Errorf("%w: malformed node identity extension", ErrCertificateInvalid)
			}
			sum := sha256.Sum256(raw)
			return ed25519.PublicKey(raw), formatFingerprint(sum[:10]), nil
		}
	}
	return nil, "", fmt.Errorf("%w: node identity extension is missing", ErrCertificateInvalid)
}

func (m *CertificateManager) artifactPaths(serial string) (string, string) {
	return filepath.Join(m.dir, "cert-"+serial+".pem"), filepath.Join(m.dir, "key-"+serial+".pem")
}

func (m *CertificateManager) statePath() string {
	return filepath.Join(m.dir, "state.json")
}

func (m *CertificateManager) loadState() error {
	raw, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(m.statePath())
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("mTLS state permissions are too permissive; expected 0600")
	}
	if err := json.Unmarshal(raw, &m.state); err != nil {
		return fmt.Errorf("decode mTLS state: %w", err)
	}
	if m.state.Version != 1 {
		return fmt.Errorf("unsupported mTLS state version %d", m.state.Version)
	}
	if m.state.Revocations == nil {
		m.state.Revocations = map[string]CertificateRevocation{}
	}
	if m.state.Rollouts == nil {
		m.state.Rollouts = map[string]CertificateRollout{}
	}
	if m.state.AcceptedPeerCertificates == nil {
		m.state.AcceptedPeerCertificates = map[string]PeerCertificateAcceptance{}
	}
	return nil
}

func (m *CertificateManager) persistState() error {
	encoded, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(m.statePath(), encoded, 0o600)
}

func (m *CertificateManager) recordEvent(action, serial, correlationID string) {
	m.state.Events = append(m.state.Events, CertificateEvent{
		Action: action, Serial: serial, CorrelationID: correlationID, CreatedAt: m.now(),
	})
}

func atomicWrite(path string, contents []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".jolt-key-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

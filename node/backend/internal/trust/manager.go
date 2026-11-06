package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
)

// ControlTowerName is the subject of the client certificate the Control Tower
// presents. A certificate from the same authority with another name is not
// accepted on the node's API.
const ControlTowerName = "Jolt Control Tower"

// Store keeps the enrollment state.
type Store interface {
	GetManagedTrust(context.Context) (entities.ManagedTrust, error)
	PutManagedTrust(context.Context, entities.ManagedTrust) error
}

// Manager is a node's view of the authority that enrolled it. A node that was
// never enrolled has a Manager that reports Managed() == false and changes
// nothing about how it is configured.
type Manager struct {
	store Store
	now   func() time.Time
	// yamlKeys are the authorization keys written in node.yaml; they stay
	// trusted beside the bundle's so a migration never locks anyone out.
	yamlKeys map[string]ed25519.PublicKey

	mu      sync.RWMutex
	state   entities.ManagedTrust
	bundle  Bundle
	managed bool
	cert    *tls.Certificate
}

// Load reads the enrollment state, if there is one.
func Load(ctx context.Context, store Store, yamlKeys map[string]ed25519.PublicKey, now func() time.Time) (*Manager, error) {
	if now == nil {
		now = time.Now
	}
	m := &Manager{store: store, now: now, yamlKeys: yamlKeys}
	state, err := store.GetManagedTrust(ctx)
	if errors.Is(err, contracts.ErrNotFound) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := m.apply(state); err != nil {
		return nil, fmt.Errorf("stored managed trust: %w", err)
	}
	return m, nil
}

func (m *Manager) apply(state entities.ManagedTrust) error {
	bundle, err := ParseBundle([]byte(state.Bundle))
	if err != nil {
		return err
	}
	cert, err := loadPair(state.APICertPEM, state.APIKey)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.state, m.bundle, m.managed, m.cert = state, bundle, true, cert
	m.mu.Unlock()
	return nil
}

func loadPair(certPEM, keyB64 string) (*tls.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, errors.New("stored API key is malformed")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("stored API key is malformed")
	}
	var chain [][]byte
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("stored API certificate is malformed")
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("stored API certificate is malformed")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, errors.New("stored API certificate is malformed")
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	private, isEC := key.(*ecdsa.PrivateKey)
	if !ok || !isEC || !public.Equal(&private.PublicKey) {
		return nil, errors.New("stored API certificate does not match its key")
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}

// Managed reports whether the Control Tower's authority enrolled this node.
func (m *Manager) Managed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.managed
}

// BundleVersion is the version of the bundle in use, or 0.
func (m *Manager) BundleVersion() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle.Version
}

// AuthorizationKeys are the keys a signed context may carry: the ones in
// node.yaml and the unexpired ones in the bundle.
func (m *Manager) AuthorizationKeys() map[string]ed25519.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make(map[string]ed25519.PublicKey, len(m.yamlKeys))
	for id, key := range m.yamlKeys {
		keys[id] = key
	}
	if m.managed {
		for id, key := range m.bundle.PublicKeys(m.now()) {
			if _, taken := keys[id]; !taken {
				keys[id] = key
			}
		}
	}
	return keys
}

// Enroll installs the first bundle and certificate. The bundle must carry a
// root with the pinned fingerprint and be signed by one of its own keys, which
// is the only time a bundle is accepted without a predecessor.
func (m *Manager) Enroll(ctx context.Context, pin string, bundle Bundle, certPEM string, keyDER []byte, operationalHash string) error {
	m.mu.RLock()
	already := m.managed
	m.mu.RUnlock()
	if already {
		return errors.New("this node is already enrolled")
	}
	if !lowercaseHex(operationalHash) || len(operationalHash) != 64 {
		return errors.New("the operational token hash must be a SHA-256")
	}
	if err := VerifyBundle(bundle, nil, pin, m.now()); err != nil {
		return err
	}
	keyB64 := base64.StdEncoding.EncodeToString(keyDER)
	if _, err := loadPair(certPEM, keyB64); err != nil {
		return err
	}
	if err := m.checkServerChain(bundle, certPEM); err != nil {
		return err
	}
	encoded, err := bundle.Marshal()
	if err != nil {
		return err
	}
	now := m.now().UTC()
	state := entities.ManagedTrust{RootPin: pin, Bundle: string(encoded), APICertPEM: certPEM, APIKey: keyB64, OperationalHash: operationalHash, EnrolledAt: now, UpdatedAt: now}
	if err := m.store.PutManagedTrust(ctx, state); err != nil {
		return err
	}
	return m.apply(state)
}

// TokenStore is the part of the node's token state the enrollment touches.
type TokenStore interface {
	GetOperationalTokenState(context.Context) (entities.OperationalTokenState, error)
	RecoverOperationalToken(ctx context.Context, hash, correlation string, now time.Time) error
}

// EnsureOperationalToken makes the token the node chose at enrollment valid, if
// the token state has never been written. It is what finishes an enrollment
// that a crash interrupted between its two writes. A token state that already
// exists, such as one a rotation produced, is left alone.
func (m *Manager) EnsureOperationalToken(ctx context.Context, tokens TokenStore) error {
	m.mu.RLock()
	managed, hash := m.managed, m.state.OperationalHash
	m.mu.RUnlock()
	if !managed || hash == "" {
		return nil
	}
	if _, err := tokens.GetOperationalTokenState(ctx); !errors.Is(err, contracts.ErrNotFound) {
		return err
	}
	return tokens.RecoverOperationalToken(ctx, hash, "managed-enrollment", m.now().UTC())
}

// Adopt takes a newer bundle if it passes every rule in VerifyBundle against
// the one in use. A repeated delivery of the current version is a no-op.
func (m *Manager) Adopt(ctx context.Context, candidate Bundle) error {
	m.mu.RLock()
	managed, current, state := m.managed, m.bundle, m.state
	m.mu.RUnlock()
	if !managed {
		return errors.New("this node is not enrolled")
	}
	if candidate.Version == current.Version {
		a, errA := candidate.Marshal()
		b, errB := current.Marshal()
		if errA == nil && errB == nil && string(a) == string(b) {
			return nil
		}
	}
	if err := VerifyBundle(candidate, &current, "", m.now()); err != nil {
		return err
	}
	encoded, err := candidate.Marshal()
	if err != nil {
		return err
	}
	state.Bundle, state.UpdatedAt = string(encoded), m.now().UTC()
	if err := m.store.PutManagedTrust(ctx, state); err != nil {
		return err
	}
	return m.apply(state)
}

// PrepareCSR starts a renewal of the API certificate: it makes a new key, keeps
// it beside the current one, and returns a request for it. Asking again before
// the certificate arrives replaces the pending key.
func (m *Manager) PrepareCSR(ctx context.Context, nodeID string, names []string) ([]byte, error) {
	m.mu.RLock()
	managed, state := m.managed, m.state
	m.mu.RUnlock()
	if !managed {
		return nil, errors.New("this node is not enrolled")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeID}}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if name != "" {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, err
	}
	state.PendingKey, state.UpdatedAt = base64.StdEncoding.EncodeToString(der), m.now().UTC()
	if err := m.store.PutManagedTrust(ctx, state); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.state = state
	m.mu.Unlock()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}), nil
}

// InstallCertificate puts a certificate issued for the pending key into
// service. It must match the key, chain to a root in the bundle and be usable
// by a server; anything else leaves the current certificate untouched.
func (m *Manager) InstallCertificate(ctx context.Context, certPEM string) error {
	m.mu.RLock()
	managed, state, bundle := m.managed, m.state, m.bundle
	m.mu.RUnlock()
	if !managed {
		return errors.New("this node is not enrolled")
	}
	if state.PendingKey == "" {
		return errors.New("no certificate request is pending")
	}
	if _, err := loadPair(certPEM, state.PendingKey); err != nil {
		return err
	}
	if err := m.checkServerChain(bundle, certPEM); err != nil {
		return err
	}
	state.APICertPEM, state.APIKey, state.PendingKey, state.UpdatedAt = certPEM, state.PendingKey, "", m.now().UTC()
	if err := m.store.PutManagedTrust(ctx, state); err != nil {
		return err
	}
	return m.apply(state)
}

func (m *Manager) checkServerChain(bundle Bundle, certPEM string) error {
	roots, intermediates, err := bundle.Certificates()
	if err != nil {
		return err
	}
	var chain []*x509.Certificate
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return errors.New("no certificate")
	}
	if bundle.Revoked(chain[0].SerialNumber.Text(16)) {
		return errors.New("the certificate was revoked")
	}
	return Chain(chain[0], roots, append(intermediates, chain[1:]...), x509.ExtKeyUsageServerAuth, m.now())
}

// CertificateEnd is when the API certificate in use ends.
func (m *Manager) CertificateEnd() (time.Time, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil || m.cert.Leaf == nil {
		return time.Time{}, ""
	}
	return m.cert.Leaf.NotAfter, m.cert.Leaf.SerialNumber.Text(16)
}

// TLSConfig serves the API with the managed certificate and picks up a renewed
// one without a restart. A client certificate, when one is presented, must come
// from the authority, carry the Control Tower's name and not be revoked; with
// requireClient the API refuses a connection that presents none.
func (m *Manager) TLSConfig(requireClient bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.cert == nil {
				return nil, errors.New("no API certificate")
			}
			return m.cert, nil
		},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			m.mu.RLock()
			bundle, cert := m.bundle, m.cert
			m.mu.RUnlock()
			roots, _, err := bundle.Certificates()
			if err != nil || cert == nil {
				return nil, errors.New("no trust bundle")
			}
			pool := x509.NewCertPool()
			for _, root := range roots {
				pool.AddCert(root)
			}
			clientAuth := tls.VerifyClientCertIfGiven
			if requireClient {
				clientAuth = tls.RequireAndVerifyClientCert
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*cert},
				ClientCAs:    pool,
				ClientAuth:   clientAuth,
				VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
					if len(raw) == 0 && !requireClient {
						return nil
					}
					return verifyClient(bundle, chains, m.now())
				},
			}, nil
		},
	}
}

func verifyClient(bundle Bundle, chains [][]*x509.Certificate, now time.Time) error {
	for _, chain := range chains {
		leaf := chain[0]
		if leaf.Subject.CommonName != ControlTowerName || bundle.Revoked(leaf.SerialNumber.Text(16)) || now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
			continue
		}
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				return nil
			}
		}
	}
	return errors.New("client certificate is not the Control Tower's")
}

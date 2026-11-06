package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

const (
	// SigningKeyValidity is how long a context-signing key may be published.
	SigningKeyValidity = 90 * 24 * time.Hour
	// SigningRotateAfter is when a successor is created and published beside it.
	SigningRotateAfter = 60 * 24 * time.Hour
	// SigningPromoteAfter is how long a published successor waits before it
	// starts to sign. Nodes learn of it in the meantime.
	SigningPromoteAfter = 7 * 24 * time.Hour
	// SigningOverlap is how long, from the successor's creation, the key it
	// replaces stays in the bundle.
	SigningOverlap = 14 * 24 * time.Hour

	stateActive  = "active"
	statePending = "pending"
	stateRetired = "retired"
	stateCurrent = "current"

	keepBundles = 5
)

// ErrRootUnavailable means an intermediate had to be issued and the root key
// is not in the database.
var ErrRootUnavailable = errors.New("the root key is not available to renew the intermediate")

// Repository is the part of the store the manager uses.
type Repository interface {
	ListPKIObjects(ctx context.Context) ([]store.PKIObject, error)
	SavePKIObjects(ctx context.Context, put []store.PKIObject, remove []string) error
}

// Options configures a Manager.
type Options struct {
	// Key is the database encryption key. Each kind of secret is sealed under
	// a key derived from it for that kind alone.
	Key []byte
	// Names are the DNS names and IP addresses the HTTPS certificate covers.
	Names []string
	// LeafValidity defaults to DefaultLeafValidity.
	LeafValidity time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

// Item is one line of the certificate inventory. It never carries a secret.
type Item struct {
	Kind        string    `json:"kind"`
	Subject     string    `json:"subject"`
	State       string    `json:"state"`
	Serial      string    `json:"serial,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
}

type signingKey struct {
	object  store.PKIObject
	private ed25519.PrivateKey // only the active key is unsealed
	public  ed25519.PublicKey
}

// Manager owns the Control Tower's certificate authority and keeps its life
// cycle: it creates what is missing, renews at two thirds of a lifetime and
// publishes a signed bundle whenever what nodes must trust changes.
type Manager struct {
	repo Repository
	opts Options

	ensure sync.Mutex // serializes Ensure

	mu          sync.RWMutex
	signing     ed25519.PrivateKey
	signingID   string
	verifying   map[string]ed25519.PublicKey
	bundle      Bundle
	bundleJSON  []byte
	root        *x509.Certificate
	httpsLeaf   *tls.Certificate
	httpsParsed *x509.Certificate
	inventory   []Item
}

// NewManager builds a manager. Call Ensure before using it.
func NewManager(repo Repository, opts Options) (*Manager, error) {
	if len(opts.Key) != 32 {
		return nil, errors.New("the PKI needs the 32-byte database key")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LeafValidity == 0 {
		opts.LeafValidity = DefaultLeafValidity
	}
	if opts.LeafValidity < MinLeafValidity || opts.LeafValidity > MaxLeafValidity {
		return nil, fmt.Errorf("certificate validity must be between %s and %s", MinLeafValidity, MaxLeafValidity)
	}
	return &Manager{repo: repo, opts: opts}, nil
}

func (m *Manager) sealKey(kind string) []byte {
	derived := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, m.opts.Key, nil, []byte("jolt-pki-v1:"+kind)), derived)
	return derived
}

func (m *Manager) seal(kind string, secret []byte) (string, error) {
	return security.Encrypt(m.sealKey(kind), base64.StdEncoding.EncodeToString(secret))
}

func (m *Manager) unseal(kind, sealed string) ([]byte, error) {
	plain, err := security.Decrypt(m.sealKey(kind), sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal %s: %w", kind, err)
	}
	return base64.StdEncoding.DecodeString(plain)
}

func renewDue(notBefore, notAfter, now time.Time) bool {
	return !now.Before(notBefore.Add(notAfter.Sub(notBefore) * 2 / 3))
}

func parseECKey(der []byte) (*ecdsa.PrivateKey, error) { return x509.ParseECPrivateKey(der) }

func (m *Manager) authority(kind string, object store.PKIObject) (*Authority, error) {
	cert, err := ParseCertificate([]byte(object.Public))
	if err != nil {
		return nil, err
	}
	der, err := m.unseal(kind, object.Secret)
	if err != nil {
		return nil, err
	}
	key, err := parseECKey(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key}, nil
}

func newSigningKeyID(now time.Time) string {
	suffix := make([]byte, 2)
	_, _ = rand.Read(suffix)
	return "ct-" + now.UTC().Format("20060102") + "-" + hex.EncodeToString(suffix)
}

// Ensure brings the authority up to date: it creates a missing root,
// intermediate, signing key and bundle, renews what is due, retires what is
// old and rebuilds the HTTPS certificate. Everything it changes is written in
// one transaction, so a crash leaves either the old state or the new one.
func (m *Manager) Ensure(ctx context.Context) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	now := m.opts.Now().UTC()
	objects, err := m.repo.ListPKIObjects(ctx)
	if err != nil {
		return err
	}
	var put []store.PKIObject
	var remove []string
	byID := map[string]*store.PKIObject{}
	for i := range objects {
		byID[objects[i].ID] = &objects[i]
	}
	touch := func(object store.PKIObject) {
		for i := range put {
			if put[i].ID == object.ID {
				put[i] = object
				return
			}
		}
		put = append(put, object)
	}

	// Root: created once, and read back only to sign an intermediate.
	var rootObject *store.PKIObject
	for i := range objects {
		if objects[i].Kind == store.PKIRoot && objects[i].State == stateActive {
			rootObject = &objects[i]
		}
	}
	if rootObject == nil {
		root, err := NewRoot(now)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(root.Key)
		if err != nil {
			return err
		}
		sealed, err := m.seal(store.PKIRoot, der)
		if err != nil {
			return err
		}
		created := store.PKIObject{ID: "root-" + Fingerprint(root.Cert)[:12], Kind: store.PKIRoot, State: stateActive,
			Serial: root.Cert.SerialNumber.Text(16), Fingerprint: Fingerprint(root.Cert), Public: string(root.PEM()), Secret: sealed,
			NotBefore: root.Cert.NotBefore, NotAfter: root.Cert.NotAfter, CreatedAt: now}
		touch(created)
		objects = append(objects, created)
		rootObject = &objects[len(objects)-1]
	}
	rootCert, err := ParseCertificate([]byte(rootObject.Public))
	if err != nil {
		return err
	}

	renewalBlocked := false
	// Intermediate: the newest active one issues; older ones stay until they
	// expire, because leaves issued under them are still valid.
	var issuer *store.PKIObject
	for i := range objects {
		if objects[i].Kind == store.PKIIntermediate && objects[i].State == stateActive && (issuer == nil || objects[i].CreatedAt.After(issuer.CreatedAt)) {
			issuer = &objects[i]
		}
	}
	if issuer == nil || renewDue(issuer.NotBefore, issuer.NotAfter, now) {
		if rootObject.Secret == "" {
			if issuer == nil || !now.Before(issuer.NotAfter) {
				return ErrRootUnavailable
			}
			// The renewal is due but waits for a person to bring the root
			// back. Everything else keeps running, and the pass says so at
			// the end.
			renewalBlocked = true
		} else {
			root, err := m.authority(store.PKIRoot, *rootObject)
			if err != nil {
				return err
			}
			next, err := root.NewIntermediate(now)
			if err != nil {
				return err
			}
			der, err := x509.MarshalECPrivateKey(next.Key)
			if err != nil {
				return err
			}
			sealed, err := m.seal(store.PKIIntermediate, der)
			if err != nil {
				return err
			}
			if issuer != nil {
				issuer.State = stateRetired
				touch(*issuer)
			}
			created := store.PKIObject{ID: "intermediate-" + next.Cert.SerialNumber.Text(16), Kind: store.PKIIntermediate, State: stateActive,
				Serial: next.Cert.SerialNumber.Text(16), Fingerprint: Fingerprint(next.Cert), Public: string(next.PEM()), Secret: sealed,
				NotBefore: next.Cert.NotBefore, NotAfter: next.Cert.NotAfter, CreatedAt: now}
			touch(created)
			objects = append(objects, created)
			issuer = &objects[len(objects)-1]
		}
	}
	for i := range objects {
		if objects[i].Kind == store.PKIIntermediate && objects[i].State == stateRetired && now.After(objects[i].NotAfter) {
			remove = append(remove, objects[i].ID)
			objects[i].Kind = "" // out of the view below
		}
	}

	// Signing keys.
	keys, err := m.manageSigningKeys(objects, now, touch, &remove)
	if err != nil {
		return err
	}
	var active *signingKey
	for i := range keys {
		if keys[i].object.State == stateActive {
			active = &keys[i]
		}
	}

	// Bundle: published again only when what nodes trust has changed.
	var roots, issuers []string
	roots = append(roots, rootObject.Public)
	var issuerList []store.PKIObject
	for _, object := range objects {
		if object.Kind == store.PKIIntermediate {
			issuerList = append(issuerList, object)
		}
	}
	sort.Slice(issuerList, func(i, j int) bool { return issuerList[i].CreatedAt.Before(issuerList[j].CreatedAt) })
	for _, object := range issuerList {
		issuers = append(issuers, object.Public)
	}
	var published []BundleKey
	for _, key := range keys {
		published = append(published, BundleKey{ID: key.object.ID[len("signing-"):], Key: base64.StdEncoding.EncodeToString(key.public), NotAfter: key.object.NotAfter})
	}
	sort.Slice(published, func(i, j int) bool { return published[i].ID < published[j].ID })
	var latest *store.PKIObject
	for i := range objects {
		if objects[i].Kind == store.PKIBundle && (latest == nil || objects[i].ID > latest.ID) {
			latest = &objects[i]
		}
	}
	desired := Bundle{Roots: roots, Intermediates: issuers, SigningKeys: published, RevokedSerials: []string{}}
	var current Bundle
	if latest != nil {
		if current, err = ParseBundle([]byte(latest.Public)); err != nil {
			return fmt.Errorf("stored trust bundle: %w", err)
		}
		desired.RevokedSerials = current.RevokedSerials
	}
	if latest == nil || !sameTrust(current, desired) {
		desired.Version, desired.IssuedAt = current.Version+1, now
		signed, err := desired.Sign(active.object.ID[len("signing-"):], active.private)
		if err != nil {
			return err
		}
		encoded, err := signed.Marshal()
		if err != nil {
			return err
		}
		created := store.PKIObject{ID: fmt.Sprintf("bundle-%012d", signed.Version), Kind: store.PKIBundle, State: stateCurrent,
			Public: string(encoded), NotBefore: now, NotAfter: now, CreatedAt: now}
		touch(created)
		objects = append(objects, created)
		current = signed
		var bundles []store.PKIObject
		for _, object := range objects {
			if object.Kind == store.PKIBundle {
				bundles = append(bundles, object)
			}
		}
		sort.Slice(bundles, func(i, j int) bool { return bundles[i].ID < bundles[j].ID })
		for len(bundles) > keepBundles {
			remove = append(remove, bundles[0].ID)
			bundles = bundles[1:]
		}
	}

	// An object retired and removed in the same pass is simply removed.
	removed := map[string]bool{}
	for _, id := range remove {
		removed[id] = true
	}
	kept := put[:0]
	for _, object := range put {
		if !removed[object.ID] {
			kept = append(kept, object)
		}
	}
	put = kept
	if len(put) > 0 || len(remove) > 0 {
		if err := m.repo.SavePKIObjects(ctx, put, remove); err != nil {
			return err
		}
	}
	if err := m.publish(*rootObject, rootCert, *issuer, keys, current, now); err != nil {
		return err
	}
	if renewalBlocked {
		return ErrRootUnavailable
	}
	return nil
}

func sameTrust(a, b Bundle) bool {
	if len(a.Roots) != len(b.Roots) || len(a.Intermediates) != len(b.Intermediates) || len(a.SigningKeys) != len(b.SigningKeys) {
		return false
	}
	for i := range a.Roots {
		if a.Roots[i] != b.Roots[i] {
			return false
		}
	}
	for i := range a.Intermediates {
		if a.Intermediates[i] != b.Intermediates[i] {
			return false
		}
	}
	for i := range a.SigningKeys {
		if a.SigningKeys[i].ID != b.SigningKeys[i].ID || a.SigningKeys[i].Key != b.SigningKeys[i].Key || !a.SigningKeys[i].NotAfter.Equal(b.SigningKeys[i].NotAfter) {
			return false
		}
	}
	return true
}

// manageSigningKeys creates the first key, publishes a successor when the
// active key is old enough, promotes it once nodes have had time to learn of
// it, and drops the key it replaced after the overlap.
func (m *Manager) manageSigningKeys(objects []store.PKIObject, now time.Time, touch func(store.PKIObject), remove *[]string) ([]signingKey, error) {
	var keys []signingKey
	load := func(object store.PKIObject, withPrivate bool) (signingKey, error) {
		public, err := base64.StdEncoding.DecodeString(object.Public)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return signingKey{}, errors.New("stored signing key is malformed")
		}
		key := signingKey{object: object, public: ed25519.PublicKey(public)}
		if withPrivate {
			seed, err := m.unseal(store.PKISigningKey, object.Secret)
			if err != nil {
				return signingKey{}, err
			}
			if len(seed) != ed25519.SeedSize {
				return signingKey{}, errors.New("stored signing key is malformed")
			}
			key.private = ed25519.NewKeyFromSeed(seed)
			if !key.private.Public().(ed25519.PublicKey).Equal(key.public) {
				return signingKey{}, errors.New("stored signing key does not match its public key")
			}
		}
		return key, nil
	}
	create := func(state string) (signingKey, error) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return signingKey{}, err
		}
		id := newSigningKeyID(now)
		sealed, err := m.seal(store.PKISigningKey, private.Seed())
		if err != nil {
			return signingKey{}, err
		}
		sum := sha256.Sum256(public)
		object := store.PKIObject{ID: "signing-" + id, Kind: store.PKISigningKey, State: state, Fingerprint: hex.EncodeToString(sum[:]),
			Public: base64.StdEncoding.EncodeToString(public), Secret: sealed, NotBefore: now, NotAfter: now.Add(SigningKeyValidity), CreatedAt: now}
		touch(object)
		return signingKey{object: object, private: private, public: public}, nil
	}

	var active, pending *store.PKIObject
	var retiring []store.PKIObject
	for i := range objects {
		if objects[i].Kind != store.PKISigningKey {
			continue
		}
		switch objects[i].State {
		case stateActive:
			active = &objects[i]
		case statePending:
			pending = &objects[i]
		default:
			retiring = append(retiring, objects[i])
		}
	}
	if active == nil {
		first, err := create(stateActive)
		if err != nil {
			return nil, err
		}
		keys = append(keys, first)
		active = &first.object
	} else {
		loaded, err := load(*active, true)
		if err != nil {
			return nil, err
		}
		keys = append(keys, loaded)
	}
	if pending != nil && !now.Before(pending.CreatedAt.Add(SigningPromoteAfter)) {
		// The successor starts to sign and the key it replaces is retired.
		old := keys[0].object
		old.State = stateRetired
		touch(old)
		promoted := *pending
		promoted.State = stateActive
		touch(promoted)
		loadedNew, err := load(promoted, true)
		if err != nil {
			return nil, err
		}
		keys = []signingKey{loadedNew}
		oldKey, _ := load(old, false)
		keys = append(keys, oldKey)
		active, pending = &promoted, nil
	} else if pending != nil {
		loaded, err := load(*pending, false)
		if err != nil {
			return nil, err
		}
		keys = append(keys, loaded)
	} else if !now.Before(active.CreatedAt.Add(SigningRotateAfter)) {
		successor, err := create(statePending)
		if err != nil {
			return nil, err
		}
		successor.private = nil
		keys = append(keys, successor)
	}
	for _, object := range retiring {
		expired := !now.Before(object.NotAfter)
		overlapOver := !now.Before(active.CreatedAt.Add(SigningOverlap))
		if expired || overlapOver {
			*remove = append(*remove, object.ID)
			continue
		}
		kept, err := load(object, false)
		if err != nil {
			return nil, err
		}
		keys = append(keys, kept)
	}
	return keys, nil
}

// publish swaps in the new in-memory view and rebuilds the HTTPS certificate
// when it is missing, due, or no longer covers the configured names.
func (m *Manager) publish(rootObject store.PKIObject, rootCert *x509.Certificate, issuerObject store.PKIObject, keys []signingKey, bundle Bundle, now time.Time) error {
	m.mu.RLock()
	leaf, parsed := m.httpsLeaf, m.httpsParsed
	m.mu.RUnlock()
	dns, ips := m.splitNames()
	if leaf == nil || parsed == nil || renewDue(parsed.NotBefore, parsed.NotAfter, now) || parsed.Issuer.CommonName != issuerCommonName(issuerObject) {
		issuer, err := m.authority(store.PKIIntermediate, issuerObject)
		if err != nil {
			return err
		}
		key, err := generateKey()
		if err != nil {
			return err
		}
		cert, err := issuer.Issue(now, &key.PublicKey, LeafSpec{CommonName: "Jolt Control Tower", DNSNames: dns, IPs: ips, Usage: x509.ExtKeyUsageServerAuth, Validity: m.opts.LeafValidity})
		if err != nil {
			return err
		}
		leaf = &tls.Certificate{Certificate: [][]byte{cert.Raw, issuer.Cert.Raw}, PrivateKey: key, Leaf: cert}
		parsed = cert
	}
	encoded, err := bundle.Marshal()
	if err != nil {
		return err
	}
	verifying := map[string]ed25519.PublicKey{}
	var signing ed25519.PrivateKey
	var signingID string
	inventory := []Item{
		item("root", rootCert.Subject.CommonName, stateActive, rootCert),
	}
	issuers, _ := parseAll(bundle.Intermediates)
	for _, cert := range issuers {
		state := stateRetired
		if cert.SerialNumber.Text(16) == issuerObject.Serial {
			state = stateActive
		}
		inventory = append(inventory, item("intermediate", cert.Subject.CommonName, state, cert))
	}
	inventory = append(inventory, item("https", "Control Tower", stateActive, parsed))
	for _, key := range keys {
		id := key.object.ID[len("signing-"):]
		if key.object.State == stateActive {
			signing, signingID = key.private, id
		}
		if key.object.State != statePending {
			verifying[id] = key.public
		}
		inventory = append(inventory, Item{Kind: "signing_key", Subject: id, State: key.object.State, Fingerprint: key.object.Fingerprint,
			NotBefore: key.object.NotBefore, NotAfter: key.object.NotAfter})
	}
	m.mu.Lock()
	m.signing, m.signingID, m.verifying = signing, signingID, verifying
	m.bundle, m.bundleJSON, m.root = bundle, encoded, rootCert
	m.httpsLeaf, m.httpsParsed, m.inventory = leaf, parsed, inventory
	m.mu.Unlock()
	return nil
}

func parseAll(values []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, value := range values {
		cert, err := ParseCertificate([]byte(value))
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func issuerCommonName(object store.PKIObject) string {
	cert, err := ParseCertificate([]byte(object.Public))
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

func item(kind, subject, state string, cert *x509.Certificate) Item {
	return Item{Kind: kind, Subject: subject, State: state, Serial: cert.SerialNumber.Text(16), Fingerprint: Fingerprint(cert), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}
}

// defaultNames are always covered, so the Control Tower answers on loopback.
var defaultNames = []string{"localhost", "127.0.0.1", "::1"}

func (m *Manager) splitNames() (dns []string, ips []net.IP) {
	seen := map[string]bool{}
	for _, name := range append(append([]string{}, defaultNames...), m.opts.Names...) {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if ip := net.ParseIP(name); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, name)
		}
	}
	return dns, ips
}

// Current is the key that signs authorization contexts now.
func (m *Manager) Current() (string, ed25519.PrivateKey) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.signingID, m.signing
}

// Public returns the keys a signed context may have been made with: the active
// key and any key still in its overlap.
func (m *Manager) Public() map[string]ed25519.PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make(map[string]ed25519.PublicKey, len(m.verifying))
	for id, key := range m.verifying {
		keys[id] = key
	}
	return keys
}

// Bundle is the trust bundle nodes are told to adopt.
func (m *Manager) Bundle() Bundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle
}

// RootPEM is the public root certificate people and agents install.
func (m *Manager) RootPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.root == nil {
		return nil
	}
	return append([]byte(nil), (&Authority{Cert: m.root}).PEM()...)
}

// RootFingerprint is the SHA-256 of the root, lowercase hex.
func (m *Manager) RootFingerprint() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.root == nil {
		return ""
	}
	return Fingerprint(m.root)
}

// Inventory lists every certificate and key with its dates. It carries no
// secret.
func (m *Manager) Inventory() []Item {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Item(nil), m.inventory...)
}

// TLSConfig serves the HTTPS certificate and picks up each renewal without a
// restart.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if m.httpsLeaf == nil {
				return nil, errors.New("the HTTPS certificate is not ready")
			}
			return m.httpsLeaf, nil
		},
	}
}

// Run keeps the authority current until ctx ends. A failed pass is reported
// and retried at the next interval; the previous view stays in use.
func (m *Manager) Run(ctx context.Context, interval time.Duration, report func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Ensure(ctx); err != nil && report != nil {
				report(err)
			}
		}
	}
}

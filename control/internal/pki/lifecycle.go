package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

// Errors a caller can tell apart.
var (
	ErrNoRotation       = errors.New("there is no root rotation to do that to")
	ErrRotationBusy     = errors.New("a root rotation is already under way")
	ErrTooManyIssuers   = errors.New("an earlier intermediate is still in use; wait for it to leave the bundle before issuing another")
	ErrUseRotation      = errors.New("this is the active intermediate: rotate it instead of revoking it")
	ErrCannotRevokeRoot = errors.New("a root is retired by a root rotation, never revoked")
	ErrTooManyRevoked   = errors.New("the revocation list is full")
)

// Rotation says where a root rotation stands.
type Rotation struct {
	// Phase is "none", "prepared" (the next root is in the bundle, nothing is
	// signed by it yet) or "promoted" (it signs, and the previous root stays
	// in the bundle for what it already issued).
	Phase    string `json:"phase"`
	Next     string `json:"next_root_fingerprint,omitempty"`
	Previous string `json:"previous_root_fingerprint,omitempty"`
}

// Revocation is one serial the bundle tells nodes to refuse.
type Revocation struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
	// NotAfter is when the certificate ends anyway; the serial leaves the
	// bundle a day later.
	NotAfter time.Time `json:"not_after"`
}

type revocationRecord struct {
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

func (m *Manager) newRootObject(now time.Time, state string) (store.PKIObject, error) {
	root, err := NewRoot(now)
	if err != nil {
		return store.PKIObject{}, err
	}
	der, err := x509.MarshalECPrivateKey(root.Key)
	if err != nil {
		return store.PKIObject{}, err
	}
	sealed, err := m.seal(store.PKIRoot, der)
	if err != nil {
		return store.PKIObject{}, err
	}
	return store.PKIObject{ID: "root-" + Fingerprint(root.Cert)[:12], Kind: store.PKIRoot, State: state,
		Serial: root.Cert.SerialNumber.Text(16), Fingerprint: Fingerprint(root.Cert), Public: string(root.PEM()), Secret: sealed,
		NotBefore: root.Cert.NotBefore, NotAfter: root.Cert.NotAfter, CreatedAt: now}, nil
}

// newIntermediateObject issues an intermediate under a root. The root key is
// the one in the database, or override when a person brings it back from a file
// for the occasion.
func (m *Manager) newIntermediateObject(root store.PKIObject, override *ecdsa.PrivateKey, now time.Time) (store.PKIObject, error) {
	var authority *Authority
	switch {
	case override != nil:
		cert, err := ParseCertificate([]byte(root.Public))
		if err != nil {
			return store.PKIObject{}, err
		}
		public, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !public.Equal(&override.PublicKey) {
			return store.PKIObject{}, errors.New("that key is not the key of this root")
		}
		authority = &Authority{Cert: cert, Key: override}
	case root.Secret == "":
		return store.PKIObject{}, ErrRootUnavailable
	default:
		loaded, err := m.authority(store.PKIRoot, root)
		if err != nil {
			return store.PKIObject{}, err
		}
		authority = loaded
	}
	next, err := authority.NewIntermediate(now)
	if err != nil {
		return store.PKIObject{}, err
	}
	der, err := x509.MarshalECPrivateKey(next.Key)
	if err != nil {
		return store.PKIObject{}, err
	}
	sealed, err := m.seal(store.PKIIntermediate, der)
	if err != nil {
		return store.PKIObject{}, err
	}
	return store.PKIObject{ID: "intermediate-" + next.Cert.SerialNumber.Text(16), Kind: store.PKIIntermediate, State: stateActive,
		Serial: next.Cert.SerialNumber.Text(16), Fingerprint: Fingerprint(next.Cert), Public: string(next.PEM()), Secret: sealed,
		NotBefore: next.Cert.NotBefore, NotAfter: next.Cert.NotAfter, CreatedAt: now}, nil
}

// view is what the lifecycle operations read from the store.
type view struct {
	objects                       []store.PKIObject
	active, next, retired         *store.PKIObject
	intermediates, revokedObjects []store.PKIObject
}

func (m *Manager) load(ctx context.Context) (view, error) {
	objects, err := m.repo.ListPKIObjects(ctx)
	if err != nil {
		return view{}, err
	}
	v := view{objects: objects}
	for i := range v.objects {
		object := &v.objects[i]
		switch object.Kind {
		case store.PKIRoot:
			switch object.State {
			case stateActive:
				v.active = object
			case stateNext:
				v.next = object
			case stateRetired:
				v.retired = object
			}
		case store.PKIIntermediate:
			v.intermediates = append(v.intermediates, *object)
		case store.PKIRevocation:
			v.revokedObjects = append(v.revokedObjects, *object)
		}
	}
	if v.active == nil {
		return view{}, errors.New("the certificate authority has no root yet")
	}
	return v, nil
}

// inBundle counts the intermediates a bundle lists: all but the revoked ones.
func (v view) inBundle() int {
	total := 0
	for _, object := range v.intermediates {
		if object.State != stateRevoked {
			total++
		}
	}
	return total
}

// Revoke tells nodes to refuse a certificate from now on. The serial joins the
// next bundle; a certificate of the Control Tower's own that was revoked is
// replaced by the next pass. Revoking the intermediate in use is refused: that
// is RotateIntermediate, which also replaces what it signed.
func (m *Manager) Revoke(ctx context.Context, revocation Revocation) error {
	serial := strings.ToLower(strings.TrimSpace(revocation.Serial))
	if !lowercaseHex(serial) {
		return errors.New("the serial must be lowercase hexadecimal")
	}
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	if v.active.Serial == serial || (v.next != nil && v.next.Serial == serial) || (v.retired != nil && v.retired.Serial == serial) {
		return ErrCannotRevokeRoot
	}
	for _, object := range v.intermediates {
		if object.Serial == serial && object.State == stateActive {
			return ErrUseRotation
		}
	}
	for _, object := range v.revokedObjects {
		if object.Serial == serial {
			return nil // already revoked: asking again changes nothing
		}
	}
	if len(v.revokedObjects) >= MaxRevokedSerials {
		return ErrTooManyRevoked
	}
	now := m.opts.Now().UTC()
	object, err := revocationObject(serial, revocation, now)
	if err != nil {
		return err
	}
	if err := m.repo.SavePKIObjects(ctx, []store.PKIObject{object}, nil); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

func revocationObject(serial string, revocation Revocation, now time.Time) (store.PKIObject, error) {
	record, err := json.Marshal(revocationRecord{Subject: revocation.Subject, Reason: revocation.Reason, RevokedAt: now})
	if err != nil {
		return store.PKIObject{}, err
	}
	end := revocation.NotAfter
	if end.IsZero() {
		end = now.Add(MaxLeafValidity)
	}
	return store.PKIObject{ID: "revocation-" + serial, Kind: store.PKIRevocation, State: stateActive, Serial: serial,
		Public: string(record), NotBefore: now, NotAfter: end.UTC(), CreatedAt: now}, nil
}

// Revocations lists what the bundle revokes, newest first.
func (m *Manager) Revocations(ctx context.Context) ([]Revocation, error) {
	objects, err := m.repo.ListPKIObjects(ctx)
	if err != nil {
		return nil, err
	}
	out := []Revocation{}
	for _, object := range objects {
		if object.Kind != store.PKIRevocation {
			continue
		}
		var record revocationRecord
		_ = json.Unmarshal([]byte(object.Public), &record)
		out = append(out, Revocation{Serial: object.Serial, Subject: record.Subject, Reason: record.Reason, RevokedAt: record.RevokedAt, NotAfter: object.NotAfter})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RevokedAt.After(out[j].RevokedAt) })
	return out, nil
}

// Revoked reports whether the bundle in use revokes a serial.
func (m *Manager) Revoked(serial string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundle.Revoked(serial)
}

// RotateIntermediate issues a new intermediate and makes it the one that signs.
// With revokePrevious, every earlier intermediate is revoked and leaves the
// bundle at once, which is the answer to a leaked issuing key: what it signed
// stops being trusted and the Control Tower reissues its own certificates in
// the same pass. Without it the previous one stays in the bundle until it
// expires, as in a planned renewal. The root key must be in the database.
func (m *Manager) RotateIntermediate(ctx context.Context, revokePrevious bool, reason string) error {
	return m.rotateIntermediate(ctx, nil, revokePrevious, reason)
}

func (m *Manager) rotateIntermediate(ctx context.Context, override *ecdsa.PrivateKey, revokePrevious bool, reason string) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	remaining := 0
	for _, object := range v.intermediates {
		if object.State != stateRevoked && !revokePrevious {
			remaining++
		}
	}
	if remaining+1 > MaxBundleIssuers {
		return ErrTooManyIssuers
	}
	now := m.opts.Now().UTC()
	created, err := m.newIntermediateObject(*v.active, override, now)
	if err != nil {
		return err
	}
	put := []store.PKIObject{created}
	for _, object := range v.intermediates {
		if object.State == stateRevoked {
			continue
		}
		if revokePrevious {
			object.State = stateRevoked
			put = append(put, object)
			revocation, err := revocationObject(object.Serial, Revocation{Subject: issuerSubject(object), Reason: nonEmpty(reason, "intermediate rotated"), NotAfter: object.NotAfter}, now)
			if err != nil {
				return err
			}
			put = append(put, revocation)
		} else if object.State == stateActive {
			object.State = stateRetired
			put = append(put, object)
		}
	}
	if err := m.repo.SavePKIObjects(ctx, put, nil); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

func issuerSubject(object store.PKIObject) string {
	if cert, err := ParseCertificate([]byte(object.Public)); err == nil {
		return cert.Subject.CommonName
	}
	return object.ID
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// BeginRootRotation creates the next root and publishes it beside the active
// one. Nothing is signed by it yet, so no node or browser has to change; the
// nodes learn of it through the bundle, and people install it from /ca before
// PromoteRoot makes the Control Tower start using it.
func (m *Manager) BeginRootRotation(ctx context.Context) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	if v.next != nil || v.retired != nil {
		return ErrRotationBusy
	}
	created, err := m.newRootObject(m.opts.Now().UTC(), stateNext)
	if err != nil {
		return err
	}
	if err := m.repo.SavePKIObjects(ctx, []store.PKIObject{created}, nil); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

// PromoteRoot makes the next root the active one. It issues an intermediate
// under it at once, so the HTTPS and client certificates and every node's API
// certificate are signed by the new chain from the next pass on; the previous
// root and its intermediates stay in the bundle for what they already issued.
func (m *Manager) PromoteRoot(ctx context.Context) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	if v.next == nil {
		return ErrNoRotation
	}
	if v.inBundle()+1 > MaxBundleIssuers {
		return ErrTooManyIssuers
	}
	now := m.opts.Now().UTC()
	promoted := *v.next
	promoted.State = stateActive
	created, err := m.newIntermediateObject(promoted, nil, now)
	if err != nil {
		return err
	}
	previous := *v.active
	previous.State = stateRetired
	put := []store.PKIObject{promoted, previous, created}
	for _, object := range v.intermediates {
		if object.State == stateActive {
			object.State = stateRetired
			put = append(put, object)
		}
	}
	if err := m.repo.SavePKIObjects(ctx, put, nil); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

// RetireRoot removes the previous root and every intermediate it signed from
// the database and the bundle. The caller decides when nothing still depends on
// them: every node holds the bundle and a certificate from the new chain.
func (m *Manager) RetireRoot(ctx context.Context) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	if v.retired == nil {
		return ErrNoRotation
	}
	old, err := ParseCertificate([]byte(v.retired.Public))
	if err != nil {
		return err
	}
	remove := []string{v.retired.ID}
	for _, object := range v.intermediates {
		cert, err := ParseCertificate([]byte(object.Public))
		if err == nil && cert.CheckSignatureFrom(old) == nil {
			remove = append(remove, object.ID)
		}
	}
	if err := m.repo.SavePKIObjects(ctx, nil, remove); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

// Rotation reports where a root rotation stands.
func (m *Manager) Rotation() Rotation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rotation
}

// UnderRetiredRoot reports whether an intermediate, named by serial, was
// signed by the root a rotation retired.
func (m *Manager) UnderRetiredRoot(issuerSerial string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.retiredIssuers[issuerSerial]
}

// NextRootPEM is the root a rotation has prepared, or nil.
func (m *Manager) NextRootPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.rotation.Phase != "prepared" {
		return nil
	}
	for _, root := range m.roots {
		if Fingerprint(root) == m.rotation.Next {
			return append([]byte(nil), (&Authority{Cert: root}).PEM()...)
		}
	}
	return nil
}

// IssuerSerial is the serial of the second certificate in a PEM chain: the
// intermediate that signed the first.
func IssuerSerial(chainPEM string) string {
	_, rest := pem.Decode([]byte(chainPEM))
	block, _ := pem.Decode(rest)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.SerialNumber.Text(16)
}

// Pin remembers the fingerprints of the API certificates this Control Tower
// issued to its nodes. A node whose certificate no longer verifies, because it
// expired while the node was away or because the intermediate that signed it
// was revoked, is still known by the exact certificate it was given: it proves
// itself with the key behind it. The set is replaced as a whole.
func (m *Manager) Pin(fingerprints []string) {
	set := make(map[string]bool, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if fingerprint != "" {
			set[fingerprint] = true
		}
	}
	m.mu.Lock()
	m.pins = set
	m.mu.Unlock()
}

// Pinned reports whether a certificate fingerprint was issued to a node.
func (m *Manager) Pinned(fingerprint string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pins[fingerprint]
}

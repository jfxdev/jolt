package pki

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/jfxdev/jolt/control/internal/store"
)

// MinRootPasswordLength is the shortest password a root key file accepts.
const MinRootPasswordLength = 16

const (
	rootBackupVersion = 1
	rootBackupDomain  = "jolt-root-key-v1\n"
	// Limits on what a file may ask the key derivation to spend, so that opening
	// a file somebody handed over cannot exhaust the host.
	maxKDFTime    = 10
	maxKDFMemory  = 1 << 20 // KiB
	maxKDFThreads = 16
)

type rootBackup struct {
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	Time        uint32 `json:"time"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Threads     uint8  `json:"threads"`
	Salt        string `json:"salt"`
	Nonce       string `json:"nonce"`
	Fingerprint string `json:"root_sha256"`
	RootPEM     string `json:"root_pem"`
	Ciphertext  string `json:"ciphertext"`
}

func (b rootBackup) additionalData() []byte {
	return []byte(rootBackupDomain + b.Fingerprint)
}

func (b rootBackup) key(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, b.Time, b.MemoryKiB, b.Threads, 32)
}

// SealRootKey writes a root key, with the certificate it belongs to, as a file
// only the password opens: Argon2id into AES-256-GCM, bound to the root's
// fingerprint.
func SealRootKey(key *ecdsa.PrivateKey, cert *x509.Certificate, password string) ([]byte, error) {
	if len(password) < MinRootPasswordLength {
		return nil, fmt.Errorf("the password must have at least %d characters", MinRootPasswordLength)
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return nil, errors.New("the key does not belong to that certificate")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	backup := rootBackup{Version: rootBackupVersion, KDF: "argon2id", Time: 3, MemoryKiB: 64 << 10, Threads: 4,
		Fingerprint: Fingerprint(cert), RootPEM: string((&Authority{Cert: cert}).PEM())}
	salt, nonce := make([]byte, 16), make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(backup.key(password, salt))
	if err != nil {
		return nil, err
	}
	backup.Salt, backup.Nonce = base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(nonce)
	backup.Ciphertext = base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, der, backup.additionalData()))
	return json.MarshalIndent(backup, "", "  ")
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// OpenRootKey reads what SealRootKey wrote. A wrong password, a file that was
// changed, or a certificate swapped for another all fail the same way.
func OpenRootKey(data []byte, password string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	var backup rootBackup
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&backup); err != nil || backup.Version != rootBackupVersion || backup.KDF != "argon2id" {
		return nil, nil, errors.New("this is not a Jolt root key file")
	}
	if backup.Time == 0 || backup.Time > maxKDFTime || backup.MemoryKiB == 0 || backup.MemoryKiB > maxKDFMemory || backup.Threads == 0 || backup.Threads > maxKDFThreads {
		return nil, nil, errors.New("the root key file asks for an unreasonable key derivation")
	}
	salt, errSalt := base64.StdEncoding.DecodeString(backup.Salt)
	nonce, errNonce := base64.StdEncoding.DecodeString(backup.Nonce)
	sealed, errSealed := base64.StdEncoding.DecodeString(backup.Ciphertext)
	if errSalt != nil || errNonce != nil || errSealed != nil || len(salt) < 16 || len(nonce) != 12 {
		return nil, nil, errors.New("this is not a Jolt root key file")
	}
	cert, err := ParseCertificate([]byte(backup.RootPEM))
	if err != nil || Fingerprint(cert) != backup.Fingerprint {
		return nil, nil, errors.New("this is not a Jolt root key file")
	}
	gcm, err := newGCM(backup.key(password, salt))
	if err != nil {
		return nil, nil, err
	}
	der, err := gcm.Open(nil, nonce, sealed, backup.additionalData())
	if err != nil {
		return nil, nil, errors.New("wrong password, or the file was changed")
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, nil, errors.New("wrong password, or the file was changed")
	}
	if public, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !public.Equal(&key.PublicKey) {
		return nil, nil, errors.New("wrong password, or the file was changed")
	}
	return key, cert, nil
}

// ExportRoot returns the active root's key as a password-protected file. It
// does not touch the database; RemoveRootKey does, once the file is safe.
func (m *Manager) ExportRoot(ctx context.Context, password string) ([]byte, error) {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return nil, err
	}
	if v.active.Secret == "" {
		return nil, errors.New("the root key is already out of the database")
	}
	authority, err := m.authority(store.PKIRoot, *v.active)
	if err != nil {
		return nil, err
	}
	data, err := SealRootKey(authority.Key, authority.Cert, password)
	if err != nil {
		return nil, err
	}
	// What was written must open with the same password before anyone removes
	// the only other copy.
	if _, _, err := OpenRootKey(data, password); err != nil {
		return nil, fmt.Errorf("the exported file did not verify: %w", err)
	}
	return data, nil
}

// RemoveRootKey takes the active root's key out of the database. It refuses
// unless proof opens with the password and belongs to this very root, so a file
// that is not the right one never replaces the stored key.
func (m *Manager) RemoveRootKey(ctx context.Context, proof []byte, password string) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	if err := m.checkRootFile(*v.active, proof, password); err != nil {
		return err
	}
	removed := *v.active
	removed.Secret = ""
	if err := m.repo.SavePKIObjects(ctx, []store.PKIObject{removed}, nil); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

func (m *Manager) checkRootFile(root store.PKIObject, file []byte, password string) error {
	key, cert, err := OpenRootKey(file, password)
	if err != nil {
		return err
	}
	stored, err := ParseCertificate([]byte(root.Public))
	if err != nil || Fingerprint(stored) != Fingerprint(cert) {
		return errors.New("that file is the key of another root")
	}
	if public, ok := stored.PublicKey.(*ecdsa.PublicKey); !ok || !public.Equal(&key.PublicKey) {
		return errors.New("that file is the key of another root")
	}
	return nil
}

// ImportRoot puts the active root's key back in the database from the file
// ExportRoot made.
func (m *Manager) ImportRoot(ctx context.Context, file []byte, password string) error {
	m.ensure.Lock()
	defer m.ensure.Unlock()
	v, err := m.load(ctx)
	if err != nil {
		return err
	}
	if err := m.checkRootFile(*v.active, file, password); err != nil {
		return err
	}
	key, _, _ := OpenRootKey(file, password)
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	sealed, err := m.seal(store.PKIRoot, der)
	if err != nil {
		return err
	}
	restored := *v.active
	restored.Secret = sealed
	if err := m.repo.SavePKIObjects(ctx, []store.PKIObject{restored}, nil); err != nil {
		return err
	}
	return m.ensureLocked(ctx)
}

// RenewIntermediateFromFile issues the next intermediate with the root key from
// a file, without ever storing that key: the way a root that lives outside the
// database renews the intermediate every two years, or answers a leak. With
// revokePrevious it behaves as RotateIntermediate does.
func (m *Manager) RenewIntermediateFromFile(ctx context.Context, file []byte, password string, revokePrevious bool, reason string) error {
	key, _, err := OpenRootKey(file, password)
	if err != nil {
		return err
	}
	return m.rotateIntermediate(ctx, key, revokePrevious, reason)
}

// RootKeyInDatabase reports whether the active root's key is stored, which is
// the default. It is false after the key was exported.
func (m *Manager) RootKeyInDatabase() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rootKeyStored
}

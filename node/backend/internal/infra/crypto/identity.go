package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

type storedIdentity struct {
	NodeID     string `json:"node_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Epoch      int    `json:"identity_epoch"`
}

type IdentityHandover struct {
	NodeID              string    `json:"node_id"`
	PreviousEpoch       int       `json:"previous_epoch"`
	NextEpoch           int       `json:"next_epoch"`
	PreviousFingerprint string    `json:"previous_fingerprint"`
	NextFingerprint     string    `json:"next_fingerprint"`
	PreviousPublicKey   string    `json:"previous_public_key"`
	NextPublicKey       string    `json:"next_public_key"`
	IssuedAt            time.Time `json:"issued_at"`
	Nonce               string    `json:"nonce"`
	PreviousSignature   string    `json:"previous_signature"`
	NextSignature       string    `json:"next_signature"`
}

type identityHandoverPayload struct {
	NodeID              string    `json:"node_id"`
	PreviousEpoch       int       `json:"previous_epoch"`
	NextEpoch           int       `json:"next_epoch"`
	PreviousFingerprint string    `json:"previous_fingerprint"`
	NextFingerprint     string    `json:"next_fingerprint"`
	PreviousPublicKey   string    `json:"previous_public_key"`
	NextPublicKey       string    `json:"next_public_key"`
	IssuedAt            time.Time `json:"issued_at"`
	Nonce               string    `json:"nonce"`
}

var (
	ErrIdentityConfirmation = errors.New("identity fingerprint confirmation does not match")
	ErrIdentityRestart      = errors.New("identity was already rotated; restart is required")
)

func LoadOrCreate(keysDir string) (entities.Identity, error) {
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return entities.Identity{}, fmt.Errorf("create keys directory: %w", err)
	}
	if err := os.Chmod(keysDir, 0o700); err != nil {
		return entities.Identity{}, fmt.Errorf("secure keys directory: %w", err)
	}
	path := filepath.Join(keysDir, "identity.json")
	_, err := os.Stat(path)
	if err == nil {
		return LoadExisting(keysDir)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return entities.Identity{}, err
	}

	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return entities.Identity{}, err
	}
	nodeBytes := make([]byte, 16)
	if _, err := rand.Read(nodeBytes); err != nil {
		return entities.Identity{}, err
	}
	stored := storedIdentity{
		NodeID:     hex.EncodeToString(nodeBytes),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		PrivateKey: base64.RawURLEncoding.EncodeToString(private),
		Epoch:      1,
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return entities.Identity{}, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return entities.Identity{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return entities.Identity{}, err
	}
	return publicIdentity(stored)
}

func LoadExisting(keysDir string) (entities.Identity, error) {
	stored, privateKey, err := loadPrivateIdentity(keysDir)
	if err != nil {
		return entities.Identity{}, err
	}
	publicKey, _, err := decodeStoredPrivate(stored)
	if err != nil {
		return entities.Identity{}, err
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return entities.Identity{}, errors.New("stored identity public and private keys do not match")
	}
	return publicIdentity(stored)
}

func publicIdentity(stored storedIdentity) (entities.Identity, error) {
	pub, err := base64.RawURLEncoding.DecodeString(stored.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return entities.Identity{}, errors.New("invalid stored public key")
	}
	sum := sha256.Sum256(pub)
	return entities.Identity{
		NodeID:      stored.NodeID,
		Fingerprint: formatFingerprint(sum[:10]),
		PublicKey:   stored.PublicKey,
		Epoch:       max(stored.Epoch, 1),
	}, nil
}

func loadPrivateIdentity(keysDir string) (storedIdentity, ed25519.PrivateKey, error) {
	path := filepath.Join(keysDir, "identity.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return storedIdentity{}, nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return storedIdentity{}, nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return storedIdentity{}, nil, errors.New("identity key permissions are too permissive; expected 0600")
	}
	var stored storedIdentity
	if err := json.Unmarshal(raw, &stored); err != nil {
		return storedIdentity{}, nil, fmt.Errorf("decode identity: %w", err)
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(stored.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return storedIdentity{}, nil, errors.New("invalid stored private key")
	}
	return stored, ed25519.PrivateKey(privateKey), nil
}

func RotateIdentity(keysDir string, active entities.Identity, confirmedFingerprint string) (entities.Identity, error) {
	stored, _, err := loadPrivateIdentity(keysDir)
	if err != nil {
		return entities.Identity{}, err
	}
	current, err := publicIdentity(stored)
	if err != nil {
		return entities.Identity{}, err
	}
	if current != active {
		return entities.Identity{}, ErrIdentityRestart
	}
	if confirmedFingerprint != current.Fingerprint {
		return entities.Identity{}, ErrIdentityConfirmation
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return entities.Identity{}, err
	}
	nextStored := storedIdentity{
		NodeID: current.NodeID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey), Epoch: current.Epoch + 1,
	}
	nextIdentity, err := publicIdentity(nextStored)
	if err != nil {
		return entities.Identity{}, err
	}
	handover, err := createIdentityHandover(stored, nextStored, nextIdentity)
	if err != nil {
		return entities.Identity{}, err
	}
	encodedNext, err := json.MarshalIndent(nextStored, "", "  ")
	if err != nil {
		return entities.Identity{}, err
	}
	encodedPrevious, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return entities.Identity{}, err
	}
	backup := filepath.Join(keysDir, "identity.previous-"+stringsNoColons(current.Fingerprint)+".json")
	if _, err := os.Stat(backup); err == nil {
		return entities.Identity{}, errors.New("previous identity backup already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return entities.Identity{}, err
	}
	if err := atomicWrite(backup, encodedPrevious, 0o600); err != nil {
		return entities.Identity{}, err
	}
	handoverEncoded, err := json.MarshalIndent(handover, "", "  ")
	if err != nil {
		_ = os.Remove(backup)
		return entities.Identity{}, err
	}
	handoverPath := filepath.Join(keysDir, fmt.Sprintf("identity-handover-%06d-%06d.json",
		handover.PreviousEpoch, handover.NextEpoch))
	if err := atomicWrite(handoverPath, handoverEncoded, 0o600); err != nil {
		_ = os.Remove(backup)
		return entities.Identity{}, err
	}
	if err := atomicWrite(filepath.Join(keysDir, "identity.json"), encodedNext, 0o600); err != nil {
		_ = os.Remove(backup)
		_ = os.Remove(handoverPath)
		return entities.Identity{}, err
	}
	return nextIdentity, nil
}

func createIdentityHandover(previous, next storedIdentity, nextIdentity entities.Identity) (IdentityHandover, error) {
	previousIdentity, err := publicIdentity(previous)
	if err != nil {
		return IdentityHandover{}, err
	}
	_, previousPrivate, err := decodeStoredPrivate(previous)
	if err != nil {
		return IdentityHandover{}, err
	}
	_, nextPrivate, err := decodeStoredPrivate(next)
	if err != nil {
		return IdentityHandover{}, err
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return IdentityHandover{}, err
	}
	now := time.Now().UTC()
	payload := identityHandoverPayload{
		NodeID: previousIdentity.NodeID, PreviousEpoch: previousIdentity.Epoch, NextEpoch: nextIdentity.Epoch,
		PreviousFingerprint: previousIdentity.Fingerprint, NextFingerprint: nextIdentity.Fingerprint,
		PreviousPublicKey: previousIdentity.PublicKey, NextPublicKey: nextIdentity.PublicKey,
		IssuedAt: now, Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return IdentityHandover{}, err
	}
	return IdentityHandover{
		NodeID: payload.NodeID, PreviousEpoch: payload.PreviousEpoch, NextEpoch: payload.NextEpoch,
		PreviousFingerprint: payload.PreviousFingerprint, NextFingerprint: payload.NextFingerprint,
		PreviousPublicKey: payload.PreviousPublicKey, NextPublicKey: payload.NextPublicKey,
		IssuedAt: payload.IssuedAt, Nonce: payload.Nonce,
		PreviousSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(previousPrivate, encoded)),
		NextSignature:     base64.RawURLEncoding.EncodeToString(ed25519.Sign(nextPrivate, encoded)),
	}, nil
}

func VerifyIdentityHandover(handover IdentityHandover, now time.Time) error {
	if handover.NodeID == "" || handover.PreviousEpoch < 1 || handover.NextEpoch != handover.PreviousEpoch+1 ||
		handover.Nonce == "" || handover.IssuedAt.IsZero() || now.Add(10*time.Minute).Before(handover.IssuedAt) {
		return errors.New("invalid identity handover")
	}
	previousPublic, previousFingerprint, err := decodeHandoverPublic(handover.PreviousPublicKey)
	if err != nil || previousFingerprint != handover.PreviousFingerprint {
		return errors.New("previous handover identity is invalid")
	}
	nextPublic, nextFingerprint, err := decodeHandoverPublic(handover.NextPublicKey)
	if err != nil || nextFingerprint != handover.NextFingerprint {
		return errors.New("next handover identity is invalid")
	}
	payload := identityHandoverPayload{
		NodeID: handover.NodeID, PreviousEpoch: handover.PreviousEpoch, NextEpoch: handover.NextEpoch,
		PreviousFingerprint: handover.PreviousFingerprint, NextFingerprint: handover.NextFingerprint,
		PreviousPublicKey: handover.PreviousPublicKey, NextPublicKey: handover.NextPublicKey,
		IssuedAt: handover.IssuedAt, Nonce: handover.Nonce,
	}
	encoded, _ := json.Marshal(payload)
	previousSignature, previousErr := base64.RawURLEncoding.DecodeString(handover.PreviousSignature)
	nextSignature, nextErr := base64.RawURLEncoding.DecodeString(handover.NextSignature)
	if previousErr != nil || nextErr != nil ||
		!ed25519.Verify(previousPublic, encoded, previousSignature) ||
		!ed25519.Verify(nextPublic, encoded, nextSignature) {
		return errors.New("identity handover signatures are invalid")
	}
	return nil
}

func LoadIdentityHandovers(keysDir string) ([]IdentityHandover, error) {
	paths, err := filepath.Glob(filepath.Join(keysDir, "identity-handover-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	handovers := make([]IdentityHandover, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var handover IdentityHandover
		if err := json.Unmarshal(raw, &handover); err != nil {
			return nil, err
		}
		handovers = append(handovers, handover)
	}
	return handovers, nil
}

func decodeHandoverPublic(encoded string) (ed25519.PublicKey, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", errors.New("invalid handover public key")
	}
	sum := sha256.Sum256(raw)
	return ed25519.PublicKey(raw), formatFingerprint(sum[:10]), nil
}

func decodeStoredPrivate(stored storedIdentity) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(stored.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, errors.New("invalid stored public key")
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(stored.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid stored private key")
	}
	return ed25519.PublicKey(publicKey), ed25519.PrivateKey(privateKey), nil
}

func stringsNoColons(value string) string {
	result := make([]byte, 0, len(value))
	for index := range value {
		if value[index] != ':' {
			result = append(result, value[index])
		}
	}
	return string(result)
}

func formatFingerprint(value []byte) string {
	encoded := stringsToUpper(hex.EncodeToString(value))
	out := ""
	for i := 0; i < len(encoded); i += 4 {
		if i > 0 {
			out += ":"
		}
		end := i + 4
		if end > len(encoded) {
			end = len(encoded)
		}
		out += encoded[i:end]
	}
	return out
}

func stringsToUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'f' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

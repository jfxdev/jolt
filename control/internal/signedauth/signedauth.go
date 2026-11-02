// Package signedauth defines a signed, short-lived authorization context.
// It is not an enforcement boundary until all relevant handlers use Verify.
package signedauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jfxdev/jolt/control/internal/filetypes"
)

const Version = 1
const MaxLifetime = 30 * time.Second
const maxPayloadBytes = filetypes.MaxContextBytes + 8192
const domain = "jolt-signed-authorization-v1\x00"

var ErrInvalid = errors.New("invalid signed authorization")

// Binding is compared in full with trusted request or persisted job metadata.
// No caller may derive its expected binding from the untrusted envelope.
type Binding struct {
	ActorID            string `json:"actor_id"`
	CredentialID       string `json:"credential_id"`
	Operation          string `json:"operation"`
	RequestID          string `json:"request_id"`
	SourceNodeID       string `json:"source_node_id"`
	SourceGrantID      string `json:"source_grant_id"`
	SourceMountID      string `json:"source_mount_id"`
	SourceRoot         string `json:"source_root"`
	DestinationNodeID  string `json:"destination_node_id"`
	DestinationGrantID string `json:"destination_grant_id"`
	DestinationMountID string `json:"destination_mount_id"`
	DestinationRoot    string `json:"destination_root"`
	PlanID             string `json:"plan_id"`
}

type Claims struct {
	Version   int             `json:"version"`
	KeyID     string          `json:"key_id"`
	Binding   Binding         `json:"binding"`
	IssuedAt  int64           `json:"issued_at"`
	ExpiresAt int64           `json:"expires_at"`
	Context   json.RawMessage `json:"context"`
}

// Sign validates the context and time interval before signing. Times are UTC
// Unix seconds so both nodes calculate the same strict expiry.
func Sign(claims Claims, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize || validate(claims) != nil {
		return "", ErrInvalid
	}
	if _, err := filetypes.DecodeContext(claims.Context); err != nil {
		return "", ErrInvalid
	}
	payload, err := json.Marshal(claims)
	if err != nil || len(payload) > maxPayloadBytes {
		return "", ErrInvalid
	}
	message := append([]byte(domain), payload...)
	signature := ed25519.Sign(key, message)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verify checks the complete trusted binding and the intended receiving node.
// The returned filter is usable only until the returned expiry. Callers must
// interrupt active streams and work at expiry and validate each renewal.
func Verify(token string, keys map[string]ed25519.PublicKey, expected Binding, receivingNode string, now time.Time) (Claims, *filetypes.Filter, error) {
	claims, filter, err := verifySigned(token, keys, now)
	if err != nil || claims.Binding != expected || receivingNode == "" || (receivingNode != expected.SourceNodeID && receivingNode != expected.DestinationNodeID) {
		return Claims{}, nil, ErrInvalid
	}
	return claims, filter, nil
}

// VerifyLocalRead checks a signed, single-node read against independently
// derived route parameters. It must only be used after operational-token auth.
// The caller must enforce expiry while streaming and never accept this token
// for jobs, uploads, peer transfers, or requests with different route targets.
func VerifyLocalRead(token string, keys map[string]ed25519.PublicKey, receivingNode, operation, mountID, root string, now time.Time) (Claims, *filetypes.Filter, error) {
	claims, filter, err := verifySigned(token, keys, now)
	if err != nil {
		return Claims{}, nil, ErrInvalid
	}
	b := claims.Binding
	switch operation {
	case "list", "metadata", "content", "archive", "archive_plan", "search", "disk_usage":
	default:
		return Claims{}, nil, ErrInvalid
	}
	if receivingNode == "" || b.SourceNodeID != receivingNode || b.SourceMountID != mountID || b.SourceRoot != root || b.Operation != operation || b.SourceGrantID != "" || b.DestinationNodeID != "" || b.DestinationGrantID != "" || b.DestinationMountID != "" || b.DestinationRoot != "" || b.PlanID != "" {
		return Claims{}, nil, ErrInvalid
	}
	return claims, filter, nil
}

// VerifyLocalUpload binds an upload authorization to the persisted session's
// actor, credential, node, mount, destination and ID independently loaded by
// the caller from trusted state. It must
// only be used after operational-token authentication and while the session is
// locked. The caller must enforce expiry throughout processing and publication.
func VerifyLocalUpload(token string, keys map[string]ed25519.PublicKey, actorID, credentialID, receivingNode, operation, mountID, destination, sessionID string, now time.Time) (Claims, *filetypes.Filter, error) {
	claims, filter, err := verifySigned(token, keys, now)
	if err != nil {
		return Claims{}, nil, ErrInvalid
	}
	if operation != "upload_chunk" && operation != "upload_complete" {
		return Claims{}, nil, ErrInvalid
	}
	b := claims.Binding
	if actorID == "" || credentialID == "" || b.ActorID != actorID || b.CredentialID != credentialID || receivingNode == "" || sessionID == "" || b.Operation != operation || b.PlanID != sessionID || b.DestinationNodeID != receivingNode || b.DestinationMountID != mountID || b.DestinationRoot != destination || b.DestinationGrantID != "" || b.SourceNodeID != "" || b.SourceGrantID != "" || b.SourceMountID != "" || b.SourceRoot != "" {
		return Claims{}, nil, ErrInvalid
	}
	return claims, filter, nil
}

func verifySigned(token string, keys map[string]ed25519.PublicKey, now time.Time) (Claims, *filetypes.Filter, error) {
	var claims Claims
	if len(token) > base64.RawURLEncoding.EncodedLen(maxPayloadBytes)+1+base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) {
		return claims, nil, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return claims, nil, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > maxPayloadBytes || filetypes.ValidateUniqueJSON(payload) != nil {
		return claims, nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil {
		return Claims{}, nil, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || validate(claims) != nil {
		return Claims{}, nil, ErrInvalid
	}
	key := keys[claims.KeyID]
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(domain), payload...), signature) {
		return Claims{}, nil, ErrInvalid
	}
	unix := now.UTC().Unix()
	if unix < claims.IssuedAt || unix >= claims.ExpiresAt {
		return Claims{}, nil, ErrInvalid
	}
	filter, err := filetypes.DecodeContext(claims.Context)
	if err != nil {
		return Claims{}, nil, ErrInvalid
	}
	return claims, filter, nil
}

func validate(c Claims) error {
	if c.Version != Version || !identifier(c.KeyID, true) || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second) {
		return ErrInvalid
	}
	b := c.Binding
	for _, value := range []string{b.ActorID, b.CredentialID, b.Operation, b.RequestID} {
		if !identifier(value, true) {
			return ErrInvalid
		}
	}
	for _, value := range []string{b.SourceNodeID, b.SourceGrantID, b.SourceMountID, b.DestinationNodeID, b.DestinationGrantID, b.DestinationMountID, b.PlanID} {
		if !identifier(value, false) {
			return ErrInvalid
		}
	}
	if b.SourceNodeID == "" && b.DestinationNodeID == "" {
		return ErrInvalid
	}
	if !endpoint(b.SourceNodeID, b.SourceGrantID, b.SourceMountID, b.SourceRoot) || !endpoint(b.DestinationNodeID, b.DestinationGrantID, b.DestinationMountID, b.DestinationRoot) {
		return ErrInvalid
	}
	if len(c.Context) == 0 || len(c.Context) > filetypes.MaxContextBytes {
		return ErrInvalid
	}
	return nil
}

func identifier(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r == 0x7f || strings.ContainsRune(`/\\?#`, r) {
			return false
		}
	}
	return true
}

// ValidKeyID reports whether an identifier can be used to select a signing key.
func ValidKeyID(value string) bool { return identifier(value, true) }

func endpoint(node, grant, mount, root string) bool {
	if node == "" {
		return grant == "" && mount == "" && root == ""
	}
	if mount == "" || root == "" || strings.TrimSpace(root) != root || len(root) > 2048 || !utf8.ValidString(root) || strings.ContainsAny(root, "\\\x00") || strings.HasPrefix(root, "/") {
		return false
	}
	if root == "." {
		return true
	}
	if path.Clean(root) != root {
		return false
	}
	for _, part := range strings.Split(root, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

package signedauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jfxdev/jolt/backend/internal/filetypes"
)

// JobLeaseRequestID derives a replay-resistant request identity from the
// persisted job ID and authorization revision. The caller must advance and
// persist the revision atomically; this function alone cannot prevent replay.
func JobLeaseRequestID(jobID string, revision uint64) string {
	if !identifier(jobID, true) || revision == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("jolt-job-lease-v1\x00%s\x00%d", jobID, revision)))
	return "job-" + hex.EncodeToString(sum[:])
}

// JobLeaseBinding validates the job topology and constructs the binding used
// for signing and verification. The expected fields must be loaded from
// trusted job state, never copied from an unverified envelope.
func JobLeaseBinding(binding Binding, revision uint64) (Binding, error) {
	requestID := JobLeaseRequestID(binding.PlanID, revision)
	if requestID == "" || binding.RequestID != "" && binding.RequestID != requestID ||
		!identifier(binding.ActorID, true) || !identifier(binding.CredentialID, true) ||
		!identifier(binding.SourceNodeID, true) || !identifier(binding.SourceMountID, true) ||
		!identifier(binding.SourceGrantID, false) || !identifier(binding.DestinationNodeID, false) || !identifier(binding.DestinationGrantID, false) || !identifier(binding.DestinationMountID, false) ||
		!endpoint(binding.SourceNodeID, binding.SourceGrantID, binding.SourceMountID, binding.SourceRoot) ||
		!endpoint(binding.DestinationNodeID, binding.DestinationGrantID, binding.DestinationMountID, binding.DestinationRoot) {
		return Binding{}, ErrInvalid
	}
	switch binding.Operation {
	case "delete":
		if binding.SourceGrantID != "" || binding.DestinationNodeID != "" {
			return Binding{}, ErrInvalid
		}
	case "copy_local", "move_local":
		if binding.SourceGrantID != "" || binding.DestinationGrantID != "" || binding.DestinationNodeID != binding.SourceNodeID || binding.DestinationMountID != binding.SourceMountID {
			return Binding{}, ErrInvalid
		}
	case "transfer_pull", "transfer_pull_directory", "transfer_pull_batch", "transfer_move_batch":
		if binding.SourceGrantID == "" || binding.DestinationGrantID == "" || binding.DestinationNodeID == "" || binding.DestinationNodeID == binding.SourceNodeID {
			return Binding{}, ErrInvalid
		}
	default:
		return Binding{}, ErrInvalid
	}
	binding.RequestID = requestID
	return binding, nil
}

// VerifyJobLease checks the complete binding and the receiving node. The
// returned filter is valid only until its signed expiry, at most 30 seconds.
// The caller must enforce expiry, trust, grants and its durable revision.
func VerifyJobLease(token string, keys map[string]ed25519.PublicKey, expected Binding, receivingNode string, revision uint64, now time.Time) (Claims, *filetypes.Filter, error) {
	binding, err := JobLeaseBinding(expected, revision)
	if err != nil {
		return Claims{}, nil, ErrInvalid
	}
	return Verify(token, keys, binding, receivingNode, now)
}

// VerifiedJobLeaseBinding extracts a candidate only after signature, time and
// context validation. The caller must still compare it with trusted job state
// and verify the persisted revision before accepting the envelope.
func VerifiedJobLeaseBinding(token string, keys map[string]ed25519.PublicKey, receivingNode string, now time.Time) (Binding, error) {
	claims, _, err := verifySigned(token, keys, now)
	if err != nil || receivingNode == "" || receivingNode != claims.Binding.SourceNodeID && receivingNode != claims.Binding.DestinationNodeID {
		return Binding{}, ErrInvalid
	}
	binding := claims.Binding
	binding.RequestID = ""
	if _, err := JobLeaseBinding(binding, 1); err != nil {
		return Binding{}, ErrInvalid
	}
	return binding, nil
}

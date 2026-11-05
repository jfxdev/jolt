package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedJobCreator interface {
	CreateJobAwaitingAuthorization(context.Context, entities.Job, string, string, string, string) (entities.Job, bool, error)
}

// CreateAwaitingSignedAuthorization validates a signed, job-bound context and
// atomically persists the job in waiting_validation. It is internal until the
// creation protocol, lease renewal and execution enforcement are integrated.
// Destructive operations require their own plan and are deliberately excluded.
func (s *Service) CreateAwaitingSignedAuthorization(ctx context.Context, request CreateRequest, nodeID, envelope, idempotencyKey string, keys map[string]ed25519.PublicKey) (entities.Job, bool, error) {
	invalid := func() (entities.Job, bool, error) { return entities.Job{}, false, ErrInvalid }
	creator, ok := s.store.(signedJobCreator)
	now := s.now().UTC()
	if !ok || request.Type != "copy_local" || request.PeerNodeID != "" || request.SourceGrantID != "" || request.DestinationGrantID != "" || idempotencyKey == "" || now.IsZero() {
		return invalid()
	}
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
	if err != nil || binding.Operation != request.Type || binding.SourceNodeID != nodeID || binding.DestinationNodeID != nodeID || binding.SourceMountID != request.MountID || binding.DestinationMountID != request.MountID || binding.SourceRoot != request.SourcePath || binding.DestinationRoot != request.Destination || binding.JobOptionsDigest == "" {
		return invalid()
	}
	request, err = s.normalizeCreateRequest(ctx, request)
	if err != nil {
		return entities.Job{}, false, err
	}
	job := s.newJob(request, "queued")
	job.ID = binding.PlanID
	options := signedauth.JobOptions{Overwrite: job.Overwrite, Recursive: job.Recursive, ConflictPolicy: job.ConflictPolicy, SourceChangePolicy: job.SourceChangePolicy, VerifyChecksum: job.VerifyChecksum, BandwidthLimit: job.BandwidthLimit, MaxParallelFiles: job.MaxParallelFiles, MaxParallelChunks: job.MaxParallelChunks, MaxAttempts: job.MaxAttempts}
	if binding.JobOptionsDigest != signedauth.JobOptionsDigest(options) {
		return invalid()
	}
	if _, _, err := signedauth.VerifyJobLease(envelope, keys, binding, nodeID, 1, now); err != nil {
		return invalid()
	}
	payload, err := json.Marshal(binding)
	if err != nil {
		return invalid()
	}
	sum := sha256.Sum256(append([]byte("jolt-signed-job-create-v1\x00"), payload...))
	requestHash := base64.RawURLEncoding.EncodeToString(sum[:])
	created, repeated, err := creator.CreateJobAwaitingAuthorization(ctx, job, binding.ActorID, binding.CredentialID, idempotencyKey, requestHash)
	if err != nil {
		return entities.Job{}, false, err
	}
	if !repeated {
		s.recordEvent(ctx, created, "job.created", "job awaiting authorization validation")
	}
	if err := ctx.Err(); err != nil {
		return entities.Job{}, false, err
	}
	return created, repeated, nil
}

package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedPlannedJobCreator interface {
	CreatePlannedJobAwaitingAuthorization(context.Context, entities.Job, []entities.JobItem, string, string, string, string) (entities.Job, bool, error)
}

// prepareSignedBatchPull normalizes a node-to-node copy into the immutable
// options its lease binds. Moves are refused: they delete the source and need a
// plan of their own.
func (s *Service) prepareSignedBatchPull(request CreateRequest) (CreateRequest, signedauth.JobOptions, error) {
	if request.Type != "transfer_pull_batch" || request.PeerNodeID == "" || request.SourceGrantID == "" || request.DestinationGrantID == "" || request.MountID == "" || s.remote == nil {
		return CreateRequest{}, signedauth.JobOptions{}, fmt.Errorf("%w: a signed remote copy needs a peer, both grants and a mount", ErrInvalid)
	}
	if request.BandwidthLimit < 0 || request.BandwidthLimit > 1<<40 || request.MaxParallelFiles < 0 || request.MaxParallelFiles > 32 || request.MaxParallelChunks < 0 || request.MaxParallelChunks > 16 {
		return CreateRequest{}, signedauth.JobOptions{}, fmt.Errorf("%w: a transfer limit is outside the supported range", ErrInvalid)
	}
	policy, err := normalizeConflictPolicy(request.ConflictPolicy, request.Overwrite)
	if err != nil {
		return CreateRequest{}, signedauth.JobOptions{}, err
	}
	if policy == "ask" {
		return CreateRequest{}, signedauth.JobOptions{}, fmt.Errorf("%w: conflict_policy ask is not supported for signed jobs", ErrInvalid)
	}
	request.ConflictPolicy, request.Recursive = policy, true
	if policy == "checksum" {
		request.VerifyChecksum = true
	}
	job := s.newJob(request, "queued")
	options := signedauth.JobOptions{Overwrite: job.Overwrite, Recursive: job.Recursive, ConflictPolicy: job.ConflictPolicy, SourceChangePolicy: job.SourceChangePolicy, VerifyChecksum: job.VerifyChecksum, BandwidthLimit: job.BandwidthLimit, MaxParallelFiles: job.MaxParallelFiles, MaxParallelChunks: job.MaxParallelChunks, MaxAttempts: job.MaxAttempts}
	return request, options, nil
}

// PrepareSignedBatchPull returns the normalized options and their digest
// without creating a job; the caller authorizes before requesting creation.
func (s *Service) PrepareSignedBatchPull(request CreateRequest) (signedauth.JobOptions, string, error) {
	_, options, err := s.prepareSignedBatchPull(request)
	if err != nil {
		return signedauth.JobOptions{}, "", err
	}
	return options, signedauth.JobOptionsDigest(options), nil
}

// SignedBatchPullHash is the idempotency hash of a signed remote copy. It
// depends only on the signed binding, so a retried request carrying a fresher
// envelope still matches the job it created.
func SignedBatchPullHash(binding signedauth.Binding) (string, error) {
	payload, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("jolt-signed-transfer-create-v1\x00"), payload...))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// CreateSignedPlannedBatchPull verifies a job-bound lease and atomically
// persists the job, in waiting_validation, together with its filtered plan.
// plan and omitted come from planning under that lease's own filter.
func (s *Service) CreateSignedPlannedBatchPull(ctx context.Context, request CreateRequest, plan entities.CopyPlan, omitted int, nodeID, envelope, idempotencyKey string, keys map[string]ed25519.PublicKey) (entities.Job, bool, error) {
	invalid := func() (entities.Job, bool, error) { return entities.Job{}, false, ErrInvalid }
	creator, ok := s.store.(signedPlannedJobCreator)
	now := s.now().UTC()
	if !ok || idempotencyKey == "" || now.IsZero() || len(plan.Items) == 0 || omitted < 0 {
		return invalid()
	}
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
	if err != nil || binding.Operation != "transfer_pull_batch" || binding.DestinationNodeID != nodeID || binding.SourceNodeID != request.PeerNodeID ||
		binding.SourceGrantID != request.SourceGrantID || binding.DestinationGrantID != request.DestinationGrantID ||
		binding.DestinationMountID != request.MountID || binding.SourceRoot != request.SourcePath || binding.DestinationRoot != request.Destination || binding.JobOptionsDigest == "" {
		return invalid()
	}
	request, options, err := s.prepareSignedBatchPull(request)
	if err != nil {
		return entities.Job{}, false, err
	}
	if binding.JobOptionsDigest != signedauth.JobOptionsDigest(options) {
		return invalid()
	}
	if _, _, err := signedauth.VerifyJobLease(envelope, keys, binding, nodeID, 1, now); err != nil {
		return invalid()
	}
	job := s.newJob(request, "queued")
	job.ID = binding.PlanID
	job.BytesTotal, job.FilesTotal, job.SourcesOmitted = plan.BytesTotal, plan.FilesTotal, omitted
	items := append([]entities.JobItem(nil), plan.Items...)
	for index := range items {
		items[index].JobID = job.ID
	}
	requestHash, err := SignedBatchPullHash(binding)
	if err != nil {
		return invalid()
	}
	created, repeated, err := creator.CreatePlannedJobAwaitingAuthorization(ctx, job, items, binding.ActorID, binding.CredentialID, idempotencyKey, requestHash)
	if err != nil {
		return entities.Job{}, false, err
	}
	if !repeated {
		s.recordEvent(ctx, created, "job.created", "remote copy awaiting authorization validation")
		if omitted > 0 {
			s.recordEvent(ctx, created, "job.sources_omitted", fmt.Sprintf("%d source entries were not accessible", omitted))
		}
	}
	return created, repeated, ctx.Err()
}

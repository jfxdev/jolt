package state

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

// JobAuthorization is private operational state. The signed envelope contains
// the access context and must not be exposed in job JSON or application logs.
type JobAuthorization struct {
	JobID     string             `yaml:"job_id" json:"-"`
	Binding   signedauth.Binding `yaml:"binding" json:"-"`
	Revision  uint64             `yaml:"revision" json:"-"`
	Envelope  string             `yaml:"envelope" json:"-"`
	ExpiresAt time.Time          `yaml:"expires_at" json:"-"`
}

// JobAuthorizationStatus exposes only the stored revision and envelope digest.
// Expired leases remain visible for reconciliation, but grant no authorization.
func (s *Store) JobAuthorizationStatus(ctx context.Context, jobID string) (revision uint64, expiry time.Time, digest string, err error) {
	err = s.view(ctx, func() error {
		job, err := get[entities.Job](s, "jobs", jobID)
		if err != nil {
			return err
		}
		current, err := get[JobAuthorization](s, "job_authorizations", jobID)
		if errors.Is(err, ErrNotFound) && !job.SignedAuthBound {
			return nil
		}
		if err != nil || !job.SignedAuthBound || current.JobID != job.ID || current.Revision == 0 || current.ExpiresAt.IsZero() || current.Envelope == "" {
			return ErrInUse
		}
		sum := sha256.Sum256([]byte(current.Envelope))
		revision, expiry, digest = current.Revision, current.ExpiresAt, base64.RawURLEncoding.EncodeToString(sum[:])
		return nil
	})
	return
}

// RegisterSignedJobAuthorization derives a candidate binding from a verified
// envelope, then compares it against the stored job and next revision.
func (s *Store) RegisterSignedJobAuthorization(ctx context.Context, jobID, nodeID, envelope string, keys map[string]ed25519.PublicKey, now time.Time) (uint64, time.Time, error) {
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
	if err != nil || binding.PlanID != jobID {
		return 0, time.Time{}, ErrInUse
	}
	authorization, err := s.RenewJobAuthorization(ctx, jobID, nodeID, envelope, binding, keys, now)
	if err != nil {
		return 0, time.Time{}, err
	}
	return authorization.Revision, authorization.ExpiresAt, nil
}

// jobAuthorizationMatches compares server-derived authorization scope with
// the persisted job. Peer trust and grants are separate execution checks.
func jobAuthorizationMatches(job entities.Job, expected signedauth.Binding, nodeID string) bool {
	if job.RequiresSignedAuth && (job.SignedAuthActorID != expected.ActorID || job.SignedAuthCredentialID != expected.CredentialID) {
		return false
	}
	if job.RequiresSignedAuth && expected.JobOptionsDigest == "" || expected.JobOptionsDigest != "" && expected.JobOptionsDigest != signedauth.JobOptionsDigest(signedauth.JobOptions{Overwrite: job.Overwrite, Recursive: job.Recursive, ConflictPolicy: job.ConflictPolicy, SourceChangePolicy: job.SourceChangePolicy, VerifyChecksum: job.VerifyChecksum, BandwidthLimit: job.BandwidthLimit, MaxParallelFiles: job.MaxParallelFiles, MaxParallelChunks: job.MaxParallelChunks, MaxAttempts: job.MaxAttempts}) {
		return false
	}
	if expected.PlanID != job.ID || expected.Operation != job.Type || expected.RequestID != "" || expected.SourceRoot != job.SourcePath {
		return false
	}
	switch job.Type {
	case "delete":
		return expected.SourceNodeID == nodeID && expected.SourceMountID == job.MountID && expected.DestinationNodeID == ""
	case "copy_local", "move_local":
		return expected.SourceNodeID == nodeID && expected.DestinationNodeID == nodeID && expected.SourceMountID == job.MountID && expected.DestinationMountID == job.MountID && expected.DestinationRoot == job.Destination
	case "transfer_pull", "transfer_pull_directory", "transfer_pull_batch", "transfer_move_batch":
		return expected.SourceNodeID == job.PeerNodeID && expected.DestinationNodeID == nodeID && expected.SourceGrantID == job.SourceGrantID && expected.DestinationGrantID == job.DestinationGrantID && expected.DestinationMountID == job.MountID && expected.DestinationRoot == job.Destination
	default:
		return false
	}
}

// RenewJobAuthorization verifies and records the next revision atomically.
// The caller must supply a server-derived binding and configured public keys.
// This is internal groundwork: signature validation here does not establish
// permissions. Local copies waiting for authorization are queued again; other
// accepted jobs stay in waiting_validation.
func (s *Store) RenewJobAuthorization(ctx context.Context, jobID, nodeID, envelope string, expected signedauth.Binding, keys map[string]ed25519.PublicKey, now time.Time) (authorization JobAuthorization, err error) {
	if !signedauth.ValidKeyID(jobID) || !signedauth.ValidKeyID(nodeID) || now.IsZero() || len(envelope) == 0 {
		return JobAuthorization{}, ErrInUse
	}
	err = s.update(ctx, func(tx *transaction) error {
		job, err := get[entities.Job](s, "jobs", jobID)
		if err != nil {
			return err
		}
		switch job.State {
		case "queued", "waiting_validation", "paused", "interrupted":
		case "running":
			// A claimed local copy renews its lease while it runs.
			if !executableSecuredJob(job) {
				return ErrInUse
			}
		default:
			return ErrInUse
		}
		if !jobAuthorizationMatches(job, expected, nodeID) {
			return ErrInUse
		}
		if job.DestructivePlanID != "" {
			plan, err := get[DestructivePlan](s, "destructive_plans", job.DestructivePlanID)
			if err != nil || plan.ConsumedJobID != job.ID || plan.SubjectID != expected.ActorID {
				return ErrInUse
			}
		}
		revision := uint64(1)
		old, err := get[JobAuthorization](s, "job_authorizations", job.ID)
		if err == nil {
			if !job.SignedAuthBound || old.JobID != job.ID || old.Revision == math.MaxUint64 || old.Binding != expected {
				return ErrInUse
			}
			// A lost response may cause the exact current envelope to be
			// delivered again. Verify it with the current keys and time, but
			// do not extend its expiry or mutate the job.
			if old.Envelope == envelope {
				claims, _, err := signedauth.VerifyJobLease(envelope, keys, expected, nodeID, old.Revision, now)
				if err != nil || claims.ExpiresAt != old.ExpiresAt.Unix() {
					return ErrInUse
				}
				authorization = old
				return nil
			}
			revision = old.Revision + 1
		} else if !errors.Is(err, ErrNotFound) || job.SignedAuthBound {
			return ErrInUse
		}
		claims, _, err := signedauth.VerifyJobLease(envelope, keys, expected, nodeID, revision, now)
		if err != nil {
			return ErrInUse
		}
		if err := s.ensureSecurityVersion(5); err != nil {
			return err
		}
		authorization = JobAuthorization{JobID: job.ID, Binding: expected, Revision: revision, Envelope: envelope, ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}
		if job.State == "running" {
			// The executor owns the job record; only the lease advances.
			return tx.put("job_authorizations", job.ID, "", order(now), authorization)
		}
		job.SignedAuthBound = true
		// A local copy that stopped for lack of authorization resumes by
		// itself once a newer lease is recorded. Jobs interrupted by a restart
		// or by an operator still need an explicit resume.
		autoResume := securedJobKind(job) && (job.State == "queued" || job.State == "waiting_validation" && job.Phase == "waiting_authorization")
		switch {
		case job.State == "paused":
		case autoResume:
			job.State, job.Phase, job.Error = "queued", "validation", ""
		default:
			job.State, job.Phase, job.Error, job.NextAttemptAt = "waiting_validation", "waiting_validation", "job execution requires authorization renewal and validation", nil
		}
		job.UpdatedAt = now.UTC()
		if err := tx.put("job_authorizations", job.ID, "", order(now), authorization); err != nil {
			return err
		}
		return tx.put("jobs", job.ID, job.PeerNodeID, order(job.CreatedAt), job)
	})
	if err != nil {
		return JobAuthorization{}, err
	}
	return authorization, nil
}

// GetJobAuthorization returns the persisted binding and envelope to trusted
// runtime code. Callers must reverify it and enforce its expiration.
func (s *Store) GetJobAuthorization(ctx context.Context, jobID string) (authorization JobAuthorization, err error) {
	err = s.view(ctx, func() error {
		authorization, err = get[JobAuthorization](s, "job_authorizations", jobID)
		return err
	})
	return authorization, err
}

// ValidateJobAuthorization returns a verified snapshot of the current lease.
// Consumers must apply its filter, recheck trust and grants, enforce expiry,
// and interrupt work if a newer revision supersedes this snapshot.
func (s *Store) ValidateJobAuthorization(ctx context.Context, jobID, nodeID string, keys map[string]ed25519.PublicKey, now time.Time) (authorization JobAuthorization, filter *filetypes.Filter, err error) {
	if !signedauth.ValidKeyID(jobID) || !signedauth.ValidKeyID(nodeID) || now.IsZero() {
		return JobAuthorization{}, nil, ErrInUse
	}
	err = s.view(ctx, func() error {
		job, err := get[entities.Job](s, "jobs", jobID)
		if err != nil {
			return err
		}
		switch job.State {
		case "queued", "running", "waiting_validation":
		default:
			return ErrInUse
		}
		authorization, filter, err = s.verifiedJobLease(job, nodeID, keys, now)
		return err
	})
	if err != nil {
		return JobAuthorization{}, nil, err
	}
	return authorization, filter, nil
}

// verifiedJobLease verifies the persisted lease of a job against its server
// derived binding. The caller holds the store lock and checks the job state.
func (s *Store) verifiedJobLease(job entities.Job, nodeID string, keys map[string]ed25519.PublicKey, now time.Time) (JobAuthorization, *filetypes.Filter, error) {
	current, err := get[JobAuthorization](s, "job_authorizations", job.ID)
	if err != nil || !job.SignedAuthBound || current.JobID != job.ID || !jobAuthorizationMatches(job, current.Binding, nodeID) {
		return JobAuthorization{}, nil, ErrInUse
	}
	if job.DestructivePlanID != "" {
		plan, err := get[DestructivePlan](s, "destructive_plans", job.DestructivePlanID)
		if err != nil || plan.ConsumedJobID != job.ID || plan.SubjectID != current.Binding.ActorID {
			return JobAuthorization{}, nil, ErrInUse
		}
	}
	claims, checked, err := signedauth.VerifyJobLease(current.Envelope, keys, current.Binding, nodeID, current.Revision, now)
	if err != nil || claims.ExpiresAt != current.ExpiresAt.Unix() {
		return JobAuthorization{}, nil, ErrInUse
	}
	return current, checked, nil
}

// DestructivePlanForJob returns the confirmed plan a delete or move job runs.
// It fails unless the plan was consumed by exactly this job.
func (s *Store) DestructivePlanForJob(ctx context.Context, jobID string) (plan DestructivePlan, err error) {
	if !signedauth.ValidKeyID(jobID) {
		return DestructivePlan{}, ErrInUse
	}
	err = s.view(ctx, func() error {
		job, err := get[entities.Job](s, "jobs", jobID)
		if err != nil {
			return err
		}
		if job.DestructivePlanID == "" {
			return ErrInUse
		}
		current, err := get[DestructivePlan](s, "destructive_plans", job.DestructivePlanID)
		if err != nil {
			return err
		}
		if current.ConsumedJobID != job.ID || current.MountID != job.MountID || current.Source != job.SourcePath || current.Destination != job.Destination || current.Overwrite != job.Overwrite {
			return ErrInUse
		}
		plan = current
		return nil
	})
	return plan, err
}

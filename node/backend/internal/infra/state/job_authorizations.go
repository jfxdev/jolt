package state

import (
	"context"
	"crypto/ed25519"
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
// permissions. Accepted jobs stay in waiting_validation until policy checks,
// execution, grant checks and renewal delivery are fully integrated.
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
		job.SignedAuthBound = true
		if job.State != "paused" {
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
		current, err := get[JobAuthorization](s, "job_authorizations", jobID)
		if err != nil || !job.SignedAuthBound || current.JobID != job.ID || !jobAuthorizationMatches(job, current.Binding, nodeID) {
			return ErrInUse
		}
		if job.DestructivePlanID != "" {
			plan, err := get[DestructivePlan](s, "destructive_plans", job.DestructivePlanID)
			if err != nil || plan.ConsumedJobID != job.ID || plan.SubjectID != current.Binding.ActorID {
				return ErrInUse
			}
		}
		claims, checked, err := signedauth.VerifyJobLease(current.Envelope, keys, current.Binding, nodeID, current.Revision, now)
		if err != nil || claims.ExpiresAt != current.ExpiresAt.Unix() {
			return ErrInUse
		}
		authorization, filter = current, checked
		return nil
	})
	if err != nil {
		return JobAuthorization{}, nil, err
	}
	return authorization, filter, nil
}

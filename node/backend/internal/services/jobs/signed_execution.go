package jobs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

// SignedExecutionStore is the durable state signed local copies need to run:
// claiming a job whose persisted lease verifies, and guarding a running job so
// that it stops when the lease lapses or its policy context changes.
type SignedExecutionStore interface {
	ClaimNextSecuredJob(ctx context.Context, nodeID string, keys map[string]ed25519.PublicKey, now time.Time) (entities.Job, error)
	GuardJobAuthorization(parent context.Context, jobID, nodeID string, keys map[string]ed25519.PublicKey) (context.Context, *filetypes.Filter, context.CancelFunc, error)
}

// ConfigureSignedExecution enables running jobs bound to signed authorizations.
// Without it such jobs are never claimed. Call it before Start.
func (s *Service) ConfigureSignedExecution(store SignedExecutionStore, nodeID string, keys map[string]ed25519.PublicKey) {
	if store == nil || nodeID == "" || len(keys) == 0 {
		return
	}
	snapshot := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		snapshot[id] = append(ed25519.PublicKey(nil), key...)
	}
	s.signed, s.signedNodeID, s.signedKeys = store, nodeID, snapshot
}

// SignedExecutionEnabled reports whether jobs bound to signed authorizations
// run on this node.
func (s *Service) SignedExecutionEnabled() bool { return s.signed != nil }

// claimNext returns the next runnable job: an ordinary one, or else a signed
// local copy whose lease verifies.
func (s *Service) claimNext() (entities.Job, error) {
	job, err := s.store.ClaimNextJob(s.ctx, s.now())
	if !errors.Is(err, contracts.ErrNotFound) || s.signed == nil {
		return job, err
	}
	return s.signed.ClaimNextSecuredJob(s.ctx, s.signedNodeID, s.signedKeys, s.now())
}

// guardJob returns a context that carries the verified access filter and is
// canceled, with a contracts authorization error as its cause, when the job's
// authorization expires, is revoked or changes.
func (s *Service) guardJob(ctx context.Context, job entities.Job) (context.Context, context.CancelFunc, error) {
	if s.signed == nil {
		return ctx, nil, contracts.ErrJobAuthorizationUnavailable
	}
	guarded, filter, stop, err := s.signed.GuardJobAuthorization(ctx, job.ID, s.signedNodeID, s.signedKeys)
	if err != nil {
		return ctx, nil, err
	}
	access, err := filesystem.NewAccessFilter(filter, "nodes/"+s.signedNodeID+"/files/mounts/"+job.MountID)
	if err != nil {
		stop()
		return ctx, nil, contracts.ErrJobAuthorizationUnavailable
	}
	return withAccessFilter(guarded, access), stop, nil
}

func authorizationLost(err error) bool {
	return errors.Is(err, contracts.ErrJobAuthorizationUnavailable) || errors.Is(err, contracts.ErrJobAuthorizationChanged)
}

package jobs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

// SignedExecutionStore is the durable state signed local copies need to run:
// claiming a job whose persisted lease verifies, and guarding a running job so
// that it stops when the lease lapses or its policy context changes.
type SignedExecutionStore interface {
	ClaimNextSecuredJob(ctx context.Context, nodeID string, keys map[string]ed25519.PublicKey, now time.Time) (entities.Job, error)
	GuardJobAuthorization(parent context.Context, jobID, nodeID string, keys map[string]ed25519.PublicKey) (context.Context, *filetypes.Filter, context.CancelFunc, error)
	JobAuthorizationBinding(ctx context.Context, jobID string) (signedauth.Binding, error)
}

// TransferAccess carries the verified filters of a signed node-to-node copy.
// Destination is rooted at the destination node's mount and Source at the
// source node's mount, both over the same signed policy context. SourceRoot is
// the source grant's root, relative to its mount: a job's source paths are
// relative to the grant, so they are joined to it before the filter judges them.
type TransferAccess struct {
	Destination *filesystem.AccessFilter
	Source      *filesystem.AccessFilter
	SourceRoot  string
}

type transferAccessKey struct{}

// TransferAccessFrom returns the filters of a signed node-to-node copy.
func TransferAccessFrom(ctx context.Context) (TransferAccess, bool) {
	access, ok := ctx.Value(transferAccessKey{}).(TransferAccess)
	return access, ok && access.Destination != nil && access.Source != nil
}

// SourceMountPath converts a grant-relative source path to the mount-relative
// path the source filter evaluates.
func (a TransferAccess) SourceMountPath(grantRelative string) string {
	grantRelative = strings.TrimPrefix(path.Clean(grantRelative), "./")
	switch {
	case a.SourceRoot == "" || a.SourceRoot == ".":
		return grantRelative
	case grantRelative == "." || grantRelative == "":
		return a.SourceRoot
	}
	return a.SourceRoot + "/" + grantRelative
}

// WarningFor reports items that failed and source entries the filter omitted,
// by count only.
func WarningFor(failed, omitted int) error { return copyWarning(failed, omitted) }

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
	guarded = withAccessFilter(guarded, access)
	if job.Type == "transfer_pull_batch" {
		binding, err := s.signed.JobAuthorizationBinding(ctx, job.ID)
		if err != nil || binding.SourceNodeID != job.PeerNodeID || binding.DestinationNodeID != s.signedNodeID {
			stop()
			return ctx, nil, contracts.ErrJobAuthorizationUnavailable
		}
		source, err := filesystem.NewAccessFilter(filter, "nodes/"+binding.SourceNodeID+"/files/mounts/"+binding.SourceMountID)
		if err != nil {
			stop()
			return ctx, nil, contracts.ErrJobAuthorizationUnavailable
		}
		guarded = context.WithValue(guarded, transferAccessKey{}, TransferAccess{Destination: access, Source: source, SourceRoot: binding.SourceRoot})
	}
	return guarded, stop, nil
}

func authorizationLost(err error) bool {
	return errors.Is(err, contracts.ErrJobAuthorizationUnavailable) || errors.Is(err, contracts.ErrJobAuthorizationChanged)
}

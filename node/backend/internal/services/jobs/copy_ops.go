package jobs

import (
	"context"
	"errors"
	"fmt"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

// ErrAuthorizationRequired is returned when a job bound to a signed
// authorization would run without a verified access filter.
var ErrAuthorizationRequired = errors.New("job requires a verified access filter")

type accessFilterKey struct{}

func withAccessFilter(ctx context.Context, filter *filesystem.AccessFilter) context.Context {
	return context.WithValue(ctx, accessFilterKey{}, filter)
}

// copyOps are the filesystem operations a local copy performs. Ordinary jobs
// use the plain operations; jobs bound to a signed authorization carry the
// verified filter and every operation enforces it on source and destination.
type copyOps struct {
	s      *Service
	filter *filesystem.AccessFilter
}

// copyOperations selects the operation set for a job. A secured job without a
// filter is refused rather than run unfiltered.
func (s *Service) copyOperations(ctx context.Context, job entities.Job) (copyOps, error) {
	filter, _ := ctx.Value(accessFilterKey{}).(*filesystem.AccessFilter)
	if filter == nil && (job.SignedAuthBound || job.RequiresSignedAuth || job.DestructivePlanID != "") {
		return copyOps{}, ErrAuthorizationRequired
	}
	return copyOps{s: s, filter: filter}, nil
}

// plan returns the copy plan and how many source entries the filter omitted.
func (o copyOps) plan(ctx context.Context, job entities.Job) (entities.CopyPlan, int, error) {
	if o.filter != nil {
		return o.s.PlanCopyFiltered(ctx, job.MountID, job.SourcePath, job.Destination, job.ConflictPolicy, o.filter, job.VerifyChecksum)
	}
	plan, err := o.s.PlanCopy(ctx, job.MountID, job.SourcePath, job.Destination, job.ConflictPolicy, job.VerifyChecksum)
	return plan, 0, err
}

func (o copyOps) replan(ctx context.Context, mountID string, item entities.JobItem, policy string) (string, string, string, error) {
	if o.filter != nil {
		return o.s.planActionFiltered(ctx, mountID, item, policy, o.filter)
	}
	return o.s.planAction(ctx, mountID, item, policy)
}

func (o copyOps) metadata(ctx context.Context, mountID, relative string) (entities.FileEntry, error) {
	if o.filter != nil {
		return o.s.files.MetadataFiltered(ctx, mountID, relative, o.filter)
	}
	return o.s.files.Metadata(ctx, mountID, relative)
}

func (o copyOps) checksum(ctx context.Context, mountID, relative string) (string, error) {
	if o.filter != nil {
		return o.s.files.ChecksumFiltered(ctx, mountID, relative, o.filter)
	}
	return o.s.files.Checksum(ctx, mountID, relative)
}

func (o copyOps) createDirectory(ctx context.Context, mountID, relative string) error {
	if o.filter != nil {
		return o.s.files.CreateDirectoryFiltered(ctx, mountID, relative, o.filter)
	}
	return o.s.files.CreateDirectory(ctx, mountID, relative)
}

func (o copyOps) copyFile(ctx context.Context, job entities.Job, item entities.JobItem, progress func(int64, int64) error) (int64, string, error) {
	key := fmt.Sprintf("%s-%d", job.ID, item.Ordinal)
	overwrite, allowSourceChange := item.Action == "overwrite", job.SourceChangePolicy == "copy_anyway"
	if o.filter != nil {
		return o.s.files.CopyFileResumableParallelFiltered(ctx, job.MountID, item.SourcePath, item.DestinationPath, key,
			overwrite, item.BytesCompleted, o.s.chunkSize, job.MaxParallelChunks, item.Checksum,
			allowSourceChange, progress, o.filter, o.s.BandwidthLimiter(job))
	}
	return o.s.files.CopyFileResumableParallel(ctx, job.MountID, item.SourcePath, item.DestinationPath, key,
		overwrite, item.BytesCompleted, o.s.chunkSize, job.MaxParallelChunks, item.Checksum,
		allowSourceChange, progress, o.s.BandwidthLimiter(job))
}

// copyWarning reports failed items and source entries the filter omitted. It
// carries only counts, never the names of omitted entries.
func copyWarning(failed, omitted int) error {
	switch {
	case failed > 0 && omitted > 0:
		return fmt.Errorf("%w: %d item(s) could not be copied; %d source entries were not accessible", ErrWarnings, failed, omitted)
	case failed > 0:
		return fmt.Errorf("%w: %d item(s) could not be copied", ErrWarnings, failed)
	case omitted > 0:
		return fmt.Errorf("%w: %d source entries were not accessible", ErrWarnings, omitted)
	}
	return nil
}

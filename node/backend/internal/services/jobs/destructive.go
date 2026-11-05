package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

var (
	// ErrTreeChanged means the tree no longer matches what the operator saw
	// when the plan was created, so nothing is changed.
	ErrTreeChanged = errors.New("the tree changed after the plan was created; create a new plan")
	// ErrPlanRejected covers an unknown, expired or mismatched plan or token.
	ErrPlanRejected = errors.New("destructive plan was rejected")
)

// DestructivePlanStore is the durable state of destructive tree plans.
type DestructivePlanStore interface {
	CreateDestructivePlan(ctx context.Context, plan entities.DestructivePlan, now time.Time) error
	GetDestructivePlan(ctx context.Context, id, subjectType, subjectID, tokenHash string, now time.Time) (entities.DestructivePlan, error)
	AcceptDestructivePlan(ctx context.Context, id, subjectType, subjectID, tokenHash, treeDigest string, destinationExists bool, destinationDigest string, job entities.Job, idempotencyKey, requestHash string, now time.Time) (entities.Job, bool, error)
	DestructivePlanForJob(ctx context.Context, jobID string) (entities.DestructivePlan, error)
}

// DestructivePlanRequest names the tree operation to plan. The caller derives
// the subject from the authenticated actor; it is never client input.
type DestructivePlanRequest struct {
	SubjectType, SubjectID string
	Operation              string // delete or move
	MountID                string
	Source, Destination    string
	Overwrite              bool
}

// DestructivePlanSummary is what the operator confirms. Token is returned once
// and stored only as a hash.
type DestructivePlanSummary struct {
	ID                string    `json:"plan_id"`
	Token             string    `json:"token"`
	ExpiresAt         time.Time `json:"expires_at"`
	Operation         string    `json:"operation"`
	MountID           string    `json:"mount_id"`
	Source            string    `json:"source_path"`
	Destination       string    `json:"destination_path,omitempty"`
	Overwrite         bool      `json:"overwrite,omitempty"`
	Files             int64     `json:"files"`
	Directories       int64     `json:"directories"`
	Bytes             int64     `json:"bytes"`
	DestinationExists bool      `json:"destination_exists,omitempty"`
	DestinationFiles  int64     `json:"destination_files,omitempty"`
	DestinationBytes  int64     `json:"destination_bytes,omitempty"`
}

func (s *Service) planStore() (DestructivePlanStore, error) {
	store, ok := s.store.(DestructivePlanStore)
	if !ok {
		return nil, fmt.Errorf("%w: destructive plans are unavailable", ErrInvalid)
	}
	return store, nil
}

func hashPlanToken(token string) string {
	sum := sha256.Sum256([]byte("jolt-destructive-plan-token-v1\x00" + token))
	return hex.EncodeToString(sum[:])
}

// destinationState reports whether a move destination exists and, if so, its
// tree snapshot. Only an existing directory can be replaced.
func (s *Service) destinationState(ctx context.Context, mountID, destination string) (bool, filesystem.TreeSnapshot, error) {
	hidden, err := s.files.IsHiddenPath(ctx, mountID, destination)
	if err != nil {
		return false, filesystem.TreeSnapshot{}, err
	}
	if hidden {
		return false, filesystem.TreeSnapshot{}, filesystem.ErrHiddenName
	}
	existing, err := s.files.Metadata(ctx, mountID, destination)
	if errors.Is(err, filesystem.ErrNotFound) {
		return false, filesystem.TreeSnapshot{}, nil
	}
	if err != nil {
		return false, filesystem.TreeSnapshot{}, err
	}
	if existing.Type != "directory" {
		return true, filesystem.TreeSnapshot{}, fmt.Errorf("%w: only a directory can be replaced by a planned move", ErrInvalid)
	}
	snapshot, err := s.files.SnapshotDestructiveTree(ctx, mountID, destination)
	return true, snapshot, err
}

// CreateDestructivePlan inspects the tree and records a five-minute plan.
func (s *Service) CreateDestructivePlan(ctx context.Context, request DestructivePlanRequest) (DestructivePlanSummary, error) {
	store, err := s.planStore()
	if err != nil {
		return DestructivePlanSummary{}, err
	}
	if request.Operation != "delete" && request.Operation != "move" {
		return DestructivePlanSummary{}, fmt.Errorf("%w: operation must be delete or move", ErrInvalid)
	}
	if request.Operation == "delete" && (request.Destination != "" || request.Overwrite) {
		return DestructivePlanSummary{}, fmt.Errorf("%w: delete takes no destination", ErrInvalid)
	}
	snapshot, err := s.files.SnapshotDestructiveTree(ctx, request.MountID, request.Source)
	if err != nil {
		return DestructivePlanSummary{}, err
	}
	plan := entities.DestructivePlan{SubjectType: request.SubjectType, SubjectID: request.SubjectID, Operation: request.Operation, MountID: request.MountID, Source: request.Source, Destination: request.Destination, Overwrite: request.Overwrite, TreeDigest: snapshot.Digest}
	summary := DestructivePlanSummary{Operation: request.Operation, MountID: request.MountID, Source: request.Source, Destination: request.Destination, Overwrite: request.Overwrite, Files: snapshot.Files, Directories: snapshot.Directories, Bytes: snapshot.Bytes}
	if request.Operation == "move" {
		if request.Destination == "" || request.Destination == request.Source || strings.HasPrefix(request.Destination, request.Source+"/") {
			return DestructivePlanSummary{}, fmt.Errorf("%w: invalid move destination", ErrInvalid)
		}
		exists, destination, err := s.destinationState(ctx, request.MountID, request.Destination)
		if err != nil {
			return DestructivePlanSummary{}, err
		}
		if exists && !request.Overwrite {
			return DestructivePlanSummary{}, filesystem.ErrConflict
		}
		if exists {
			plan.DestinationExists, plan.DestinationDigest = true, destination.Digest
			summary.DestinationExists, summary.DestinationFiles, summary.DestinationBytes = true, destination.Files, destination.Bytes
		}
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return DestructivePlanSummary{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(random[:])
	plan.ID, plan.TokenHash = filesystem.NewID("plan"), hashPlanToken(token)
	now := s.now().UTC()
	if err := store.CreateDestructivePlan(ctx, plan, now); err != nil {
		return DestructivePlanSummary{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	summary.ID, summary.Token, summary.ExpiresAt = plan.ID, token, now.Add(5*time.Minute)
	return summary, nil
}

// AcceptDestructivePlan consumes a confirmation and creates the job. The job
// waits for its signed authorization and revalidates the tree before changing
// anything. The same idempotency key returns the same job.
func (s *Service) AcceptDestructivePlan(ctx context.Context, subjectType, subjectID, planID, token, idempotencyKey, correlationID string) (entities.Job, bool, error) {
	store, err := s.planStore()
	if err != nil {
		return entities.Job{}, false, err
	}
	if idempotencyKey == "" || len(idempotencyKey) > 256 || token == "" {
		return entities.Job{}, false, ErrPlanRejected
	}
	now := s.now().UTC()
	tokenHash := hashPlanToken(token)
	plan, err := store.GetDestructivePlan(ctx, planID, subjectType, subjectID, tokenHash, now)
	if err != nil {
		return entities.Job{}, false, ErrPlanRejected
	}
	treeDigest, destinationExists, destinationDigest := plan.TreeDigest, plan.DestinationExists, plan.DestinationDigest
	if plan.ConsumedJobID == "" {
		// Compare what is on disk now with what the operator confirmed.
		snapshot, err := s.files.SnapshotDestructiveTree(ctx, plan.MountID, plan.Source)
		if err != nil {
			return entities.Job{}, false, changedOrError(err)
		}
		treeDigest = snapshot.Digest
		if plan.Operation == "move" {
			exists, destination, err := s.destinationState(ctx, plan.MountID, plan.Destination)
			if err != nil {
				return entities.Job{}, false, changedOrError(err)
			}
			destinationExists, destinationDigest = exists, ""
			if exists {
				destinationDigest = destination.Digest
			}
		}
	}
	request := CreateRequest{Type: "delete", MountID: plan.MountID, SourcePath: plan.Source, Recursive: true, MaxAttempts: 1, CorrelationID: correlationID}
	if plan.Operation == "move" {
		request = CreateRequest{Type: "move_local", MountID: plan.MountID, SourcePath: plan.Source, Destination: plan.Destination, Overwrite: plan.Overwrite, MaxAttempts: 1, CorrelationID: correlationID}
	}
	job := s.newJob(request, "queued")
	sum := sha256.Sum256([]byte("jolt-destructive-accept-v1\x00" + plan.ID + "\x00" + idempotencyKey))
	created, repeated, err := store.AcceptDestructivePlan(ctx, plan.ID, subjectType, subjectID, tokenHash, treeDigest, destinationExists, destinationDigest, job, idempotencyKey, hex.EncodeToString(sum[:]), now)
	if errors.Is(err, contracts.ErrIdempotencyConflict) {
		return entities.Job{}, false, err
	}
	if errors.Is(err, contracts.ErrInUse) {
		// The store compares the digests; any mismatch means the tree moved on.
		return entities.Job{}, false, ErrTreeChanged
	}
	if err != nil {
		return entities.Job{}, false, err
	}
	if !repeated {
		s.recordEvent(ctx, created, "job.created", "destructive plan confirmed; waiting for authorization")
	}
	return created, repeated, nil
}

func changedOrError(err error) error {
	if errors.Is(err, filesystem.ErrNotFound) || errors.Is(err, filesystem.ErrConflict) {
		return ErrTreeChanged
	}
	return err
}

// executeDestructive revalidates the tree against the confirmed plan and only
// then deletes or moves it under the verified access filter. It cannot undo a
// removal that a cancellation or an external change interrupts.
func (s *Service) executeDestructive(ctx context.Context, job entities.Job) (int64, error) {
	filter, _ := ctx.Value(accessFilterKey{}).(*filesystem.AccessFilter)
	store, planErr := s.planStore()
	if filter == nil || planErr != nil {
		return 0, ErrAuthorizationRequired
	}
	plan, err := store.DestructivePlanForJob(ctx, job.ID)
	if err != nil || plan.MountID != job.MountID || plan.Source != job.SourcePath || (plan.Operation == "delete") != (job.Type == "delete") {
		return 0, ErrAuthorizationRequired
	}
	snapshot, err := s.files.SnapshotDestructiveTree(ctx, job.MountID, plan.Source)
	if err != nil {
		return 0, changedOrError(err)
	}
	if snapshot.Digest != plan.TreeDigest {
		return 0, ErrTreeChanged
	}
	if plan.Operation == "move" {
		exists, destination, err := s.destinationState(ctx, job.MountID, plan.Destination)
		if err != nil {
			return 0, changedOrError(err)
		}
		if exists != plan.DestinationExists || exists && destination.Digest != plan.DestinationDigest {
			return 0, ErrTreeChanged
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if plan.Operation == "delete" {
		return snapshot.Bytes, s.files.DeleteFiltered(ctx, job.MountID, plan.Source, true, filter)
	}
	return snapshot.Bytes, s.files.MoveFiltered(ctx, job.MountID, plan.Source, plan.Destination, plan.Overwrite, filter)
}

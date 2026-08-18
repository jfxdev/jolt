package jobs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
)

var (
	ErrNotFound            = errors.New("job not found")
	ErrInvalidState        = errors.New("job state does not allow this operation")
	ErrInvalid             = errors.New("invalid job request")
	ErrWarnings            = errors.New("job completed with warnings")
	ErrWaitingUserDecision = errors.New("job is waiting for a user decision")
	ErrWaitingPeer         = errors.New("job is waiting for its peer")
	ErrWaitingMount        = errors.New("job is waiting for its mount")
	ErrValidationTimeout   = errors.New("job validation timed out")
	ErrChunkTimeout        = errors.New("job chunk did not complete before the configured deadline")
	ErrNoProgress          = errors.New("job made no progress before the configured deadline")
)

type CreateRequest struct {
	Type               string
	MountID            string
	SourcePath         string
	Destination        string
	CorrelationID      string
	Overwrite          bool
	Recursive          bool
	MaxAttempts        int
	ConflictPolicy     string
	SourceChangePolicy string
	VerifyChecksum     bool
	BandwidthLimit     int64
	MaxParallelFiles   int
	MaxParallelChunks  int
	PeerNodeID         string
	SourceGrantID      string
	DestinationGrantID string
}

type RemoteExecutor interface {
	ExecutePull(context.Context, entities.Job, func(int64, int64) error) (int64, error)
	ExecuteDirectoryPull(context.Context, entities.Job, func(int64, int64, int, int) error) (int64, error)
	CleanupPull(context.Context, entities.Job) error
	CleanupDirectoryPull(context.Context, entities.Job) error
}

type Service struct {
	store                    contracts.Store
	files                    *filesystem.Service
	now                      func() time.Time
	defaultMaxAttempts       int
	defaultMaxParallelFiles  int
	defaultMaxParallelChunks int
	chunkSize                int64
	mountCheckInterval       time.Duration
	validationTimeout        time.Duration
	chunkTimeout             time.Duration
	noProgressTimeout        time.Duration
	nodeBandwidth            *byteRateLimiter
	remote                   RemoteExecutor

	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	running      map[string]context.CancelFunc
	progress     map[string]chan struct{}
	jobBandwidth map[string]*byteRateLimiter
	wake         chan struct{}
	wg           sync.WaitGroup
}

func New(store contracts.Store, files *filesystem.Service, maxAttempts ...int) *Service {
	defaultMaxAttempts := 3
	if len(maxAttempts) > 0 && maxAttempts[0] > 0 {
		defaultMaxAttempts = maxAttempts[0]
	}
	return &Service{
		store:                    store,
		files:                    files,
		now:                      func() time.Time { return time.Now().UTC() },
		defaultMaxAttempts:       defaultMaxAttempts,
		defaultMaxParallelFiles:  2,
		defaultMaxParallelChunks: 1,
		chunkSize:                16 << 20,
		mountCheckInterval:       5 * time.Second,
		validationTimeout:        2 * time.Minute,
		chunkTimeout:             5 * time.Minute,
		noProgressTimeout:        10 * time.Minute,
		wake:                     make(chan struct{}, 1),
		running:                  make(map[string]context.CancelFunc),
		progress:                 make(map[string]chan struct{}),
		jobBandwidth:             make(map[string]*byteRateLimiter),
	}
}

func (s *Service) ConfigureParallelism(maxFiles, maxChunks int) {
	if maxFiles > 0 {
		s.defaultMaxParallelFiles = maxFiles
	}
	if maxChunks > 0 {
		s.defaultMaxParallelChunks = maxChunks
	}
}

func (s *Service) ConfigureBandwidth(bytesPerSecond int64) {
	if bytesPerSecond > 0 {
		s.nodeBandwidth = newByteRateLimiter(bytesPerSecond)
	} else {
		s.nodeBandwidth = nil
	}
}

func (s *Service) ConfigureTimeouts(validation, chunk, noProgress time.Duration) {
	if validation > 0 {
		s.validationTimeout = validation
	}
	if chunk > 0 {
		s.chunkTimeout = chunk
	}
	if noProgress > 0 {
		s.noProgressTimeout = noProgress
	}
}

func (s *Service) ConfigureChunkSize(size int64) {
	if size > 0 {
		s.chunkSize = size
	}
}

func (s *Service) ConfigureMountCheckInterval(interval time.Duration) {
	if interval > 0 {
		s.mountCheckInterval = interval
	}
}

func (s *Service) ConfigureRemoteExecutor(remote RemoteExecutor) {
	s.remote = remote
}

// Start recovers jobs that were running during a previous process lifetime and
// starts a bounded local worker pool. Restored jobs remain in waiting_validation
// until an operator explicitly requests validation and resume.
func (s *Service) Start(parent context.Context, workers int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx != nil {
		return 0, nil
	}
	recovered, err := s.store.RecoverRunningJobs(parent, s.now())
	if err != nil {
		return 0, err
	}
	for _, job := range recovered {
		s.recordEvent(parent, job, "job.interrupted", job.Error)
	}
	if workers <= 0 {
		workers = 1
	}
	s.ctx, s.cancel = context.WithCancel(parent)
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	s.wg.Add(1)
	go s.mountMonitor()
	s.notify()
	return int64(len(recovered)), nil
}

func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) Create(ctx context.Context, request CreateRequest, idempotencyKey string) (entities.Job, bool, error) {
	if request.BandwidthLimit < 0 || request.BandwidthLimit > 1<<40 {
		return entities.Job{}, false, fmt.Errorf("%w: bandwidth limit is outside the supported range", ErrInvalid)
	}
	if request.MaxParallelFiles < 0 || request.MaxParallelFiles > 32 {
		return entities.Job{}, false, fmt.Errorf("%w: max parallel files is outside the supported range", ErrInvalid)
	}
	if request.MaxParallelChunks < 0 || request.MaxParallelChunks > 16 {
		return entities.Job{}, false, fmt.Errorf("%w: max parallel chunks is outside the supported range", ErrInvalid)
	}
	if request.Type == "copy_local" {
		policy, err := normalizeConflictPolicy(request.ConflictPolicy, request.Overwrite)
		if err != nil {
			return entities.Job{}, false, err
		}
		request.ConflictPolicy = policy
		sourceChangePolicy, err := normalizeSourceChangePolicy(request.SourceChangePolicy)
		if err != nil {
			return entities.Job{}, false, err
		}
		request.SourceChangePolicy = sourceChangePolicy
		if policy == "checksum" {
			request.VerifyChecksum = true
		}
	}
	if request.Type == "transfer_pull" {
		if s.remote == nil || request.PeerNodeID == "" || request.SourceGrantID == "" || request.DestinationGrantID == "" {
			return entities.Job{}, false, fmt.Errorf("%w: remote executor, peer and source/destination grants are required", ErrInvalid)
		}
		policy, err := normalizeConflictPolicy(request.ConflictPolicy, request.Overwrite)
		if err != nil {
			return entities.Job{}, false, err
		}
		request.ConflictPolicy = policy
		if policy == "checksum" {
			request.VerifyChecksum = true
		}
	}
	job := s.newJob(request, "queued")
	created, repeated, err := s.store.CreateJob(ctx, job, idempotencyKey)
	if err == nil && !repeated {
		s.recordEvent(ctx, created, "job.created", "job queued")
		s.notify()
	}
	return created, repeated, err
}

func (s *Service) CreatePlannedDirectoryPull(ctx context.Context, request CreateRequest, plan entities.CopyPlan, idempotencyKey string) (entities.Job, bool, error) {
	if request.BandwidthLimit < 0 || request.BandwidthLimit > 1<<40 {
		return entities.Job{}, false, fmt.Errorf("%w: bandwidth limit is outside the supported range", ErrInvalid)
	}
	if request.MaxParallelFiles < 0 || request.MaxParallelFiles > 32 {
		return entities.Job{}, false, fmt.Errorf("%w: max parallel files is outside the supported range", ErrInvalid)
	}
	if request.MaxParallelChunks < 0 || request.MaxParallelChunks > 16 {
		return entities.Job{}, false, fmt.Errorf("%w: max parallel chunks is outside the supported range", ErrInvalid)
	}
	if s.remote == nil || request.PeerNodeID == "" || request.SourceGrantID == "" || request.DestinationGrantID == "" {
		return entities.Job{}, false, fmt.Errorf("%w: remote executor, peer and source/destination grants are required", ErrInvalid)
	}
	policy, err := normalizeConflictPolicy(request.ConflictPolicy, request.Overwrite)
	if err != nil {
		return entities.Job{}, false, err
	}
	request.Type, request.ConflictPolicy, request.Recursive = "transfer_pull_directory", policy, true
	if policy == "checksum" {
		request.VerifyChecksum = true
	}
	job := s.newJob(request, "queued")
	job.BytesTotal, job.FilesTotal = plan.BytesTotal, plan.FilesTotal
	for index := range plan.Items {
		plan.Items[index].JobID = job.ID
	}
	created, repeated, err := s.store.CreateJobWithItems(ctx, job, plan.Items, idempotencyKey)
	if err == nil && !repeated {
		s.recordEvent(ctx, created, "job.created", "planned remote directory job queued")
		s.notify()
	}
	return created, repeated, err
}

// CreateInline records operations whose input only exists for the lifetime of the
// HTTP request (currently streaming uploads). It cannot be claimed by a worker.
func (s *Service) CreateInline(ctx context.Context, request CreateRequest, idempotencyKey string) (entities.Job, bool, error) {
	if request.BandwidthLimit < 0 || request.BandwidthLimit > 1<<40 {
		return entities.Job{}, false, fmt.Errorf("%w: bandwidth limit is outside the supported range", ErrInvalid)
	}
	job := s.newJob(request, "running")
	now := s.now()
	job.Phase, job.StartedAt = "transfer", &now
	created, repeated, err := s.store.CreateJob(ctx, job, idempotencyKey)
	if err == nil && !repeated {
		s.recordEvent(ctx, created, "job.started", "inline operation started")
	}
	return created, repeated, err
}

func (s *Service) newJob(request CreateRequest, state string) entities.Job {
	now := s.now()
	maxAttempts := request.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = s.defaultMaxAttempts
	}
	maxParallelFiles := request.MaxParallelFiles
	if maxParallelFiles <= 0 {
		maxParallelFiles = s.defaultMaxParallelFiles
	}
	maxParallelChunks := request.MaxParallelChunks
	if maxParallelChunks <= 0 {
		maxParallelChunks = s.defaultMaxParallelChunks
	}
	return entities.Job{
		ID: filesystem.NewID("job"), Type: request.Type, State: state, Phase: "validation",
		MountID: request.MountID, SourcePath: request.SourcePath, Destination: request.Destination,
		CorrelationID: request.CorrelationID, Overwrite: request.Overwrite, Recursive: request.Recursive,
		ConflictPolicy: request.ConflictPolicy, MaxAttempts: maxAttempts, CreatedAt: now, UpdatedAt: now,
		SourceChangePolicy: request.SourceChangePolicy, VerifyChecksum: request.VerifyChecksum,
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  maxParallelFiles,
		MaxParallelChunks: maxParallelChunks,
		PeerNodeID:        request.PeerNodeID, SourceGrantID: request.SourceGrantID,
		DestinationGrantID: request.DestinationGrantID,
	}
}

func (s *Service) Complete(ctx context.Context, job *entities.Job, bytes int64, operationErr error) error {
	now := s.now()
	job.UpdatedAt, job.CompletedAt = now, &now
	job.BytesCompleted, job.BytesTotal = bytes, bytes
	if operationErr != nil {
		job.State, job.Phase, job.Error = "failed", "finalization", operationErr.Error()
	} else {
		job.State, job.Phase, job.Error = "completed", "finalization", ""
	}
	job.ETASeconds, job.ETAConfidence = nil, ""
	if err := s.store.UpdateJob(ctx, *job); err != nil {
		return err
	}
	eventType := "job.completed"
	if operationErr != nil {
		eventType = "job.failed"
	}
	s.recordEvent(ctx, *job, eventType, job.Error)
	return nil
}

func (s *Service) List(ctx context.Context, limit int) ([]entities.Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.ListJobs(ctx, limit)
}

func (s *Service) Get(ctx context.Context, id string) (entities.Job, error) {
	j, err := s.store.GetJob(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return j, ErrNotFound
	}
	return j, err
}

func (s *Service) ListItems(ctx context.Context, jobID string) ([]entities.JobItem, error) {
	if _, err := s.Get(ctx, jobID); err != nil {
		return nil, err
	}
	return s.store.ListJobItems(ctx, jobID)
}

func (s *Service) PlanCopy(ctx context.Context, mountID, source, destination, conflictPolicy string, verifyChecksum ...bool) (entities.CopyPlan, error) {
	policy, err := normalizeConflictPolicy(conflictPolicy, false)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	checksumEnabled := policy == "checksum" || (len(verifyChecksum) > 0 && verifyChecksum[0])
	sourceMetadata, err := s.files.Metadata(ctx, mountID, source)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	manifest, err := s.files.Manifest(ctx, mountID, source)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	entries := manifest
	if sourceMetadata.Type == "directory" {
		entries = append([]entities.FileEntry{{
			Name: sourceMetadata.Name, Path: ".", Type: "directory",
			ModifiedAt: sourceMetadata.ModifiedAt,
		}}, manifest...)
	}
	plan := entities.CopyPlan{
		SourcePath: source, DestinationPath: destination, ConflictPolicy: policy,
		Items: make([]entities.JobItem, 0, len(entries)),
	}
	now := s.now()
	blockedDirectories := make(map[string]struct{})
	for index, entry := range entries {
		sourcePath := joinRelative(source, entry.Path)
		destinationPath := joinRelative(destination, entry.Path)
		item := entities.JobItem{
			Ordinal: index, RelativePath: entry.Path, SourcePath: sourcePath,
			DestinationPath: destinationPath, Type: entry.Type, Size: entry.Size,
			ModifiedAt: entry.ModifiedAt, State: "pending", UpdatedAt: now,
		}
		if hasBlockedParent(entry.Path, blockedDirectories) {
			item.Action = "conflict"
		} else {
			item.Action, item.DestinationPath, item.Checksum, err = s.planAction(ctx, mountID, item, policy)
			if err != nil {
				return entities.CopyPlan{}, err
			}
		}
		if item.Type == "file" && checksumEnabled && item.Checksum == "" {
			item.Checksum, err = s.files.Checksum(ctx, mountID, item.SourcePath)
			if err != nil {
				return entities.CopyPlan{}, err
			}
		}
		if item.Type == "directory" && item.Action == "conflict" {
			blockedDirectories[entry.Path] = struct{}{}
		}
		if item.Type == "file" {
			plan.FilesTotal++
			switch item.Action {
			case "copy", "overwrite":
				plan.CopyCount++
				plan.BytesTotal += item.Size
			case "rename":
				plan.RenameCount++
				plan.BytesTotal += item.Size
			case "skip":
				plan.SkipCount++
			case "conflict":
				plan.ConflictCount++
			}
		}
		plan.Items = append(plan.Items, item)
	}
	return plan, nil
}

func hasBlockedParent(relative string, blocked map[string]struct{}) bool {
	for current := path.Dir(relative); current != "." && current != "/"; current = path.Dir(current) {
		if _, exists := blocked[current]; exists {
			return true
		}
	}
	_, rootBlocked := blocked["."]
	return rootBlocked
}

func (s *Service) planAction(ctx context.Context, mountID string, item entities.JobItem, policy string) (string, string, string, error) {
	existing, err := s.files.Metadata(ctx, mountID, item.DestinationPath)
	if err != nil && !errors.Is(err, filesystem.ErrNotFound) {
		return "", item.DestinationPath, item.Checksum, err
	}
	if errors.Is(err, filesystem.ErrNotFound) {
		if item.Type == "directory" {
			return "create", item.DestinationPath, "", nil
		}
		return "copy", item.DestinationPath, item.Checksum, nil
	}
	if item.Type == "directory" {
		if existing.Type == "directory" {
			return "merge", item.DestinationPath, "", nil
		}
		return "conflict", item.DestinationPath, "", nil
	}
	if existing.Type != "file" {
		return "conflict", item.DestinationPath, item.Checksum, nil
	}
	switch policy {
	case "skip":
		return "skip", item.DestinationPath, item.Checksum, nil
	case "overwrite":
		return "overwrite", item.DestinationPath, item.Checksum, nil
	case "rename":
		renamed, err := s.uniqueDestination(ctx, mountID, item.DestinationPath)
		return "rename", renamed, item.Checksum, err
	case "checksum":
		sourceChecksum, err := s.files.Checksum(ctx, mountID, item.SourcePath)
		if err != nil {
			return "", item.DestinationPath, "", err
		}
		destinationChecksum, err := s.files.Checksum(ctx, mountID, item.DestinationPath)
		if err != nil {
			return "", item.DestinationPath, "", err
		}
		if sourceChecksum == destinationChecksum {
			return "skip", item.DestinationPath, sourceChecksum, nil
		}
		return "overwrite", item.DestinationPath, sourceChecksum, nil
	default:
		return "conflict", item.DestinationPath, item.Checksum, nil
	}
}

func (s *Service) uniqueDestination(ctx context.Context, mountID, destination string) (string, error) {
	extension := path.Ext(destination)
	base := strings.TrimSuffix(destination, extension)
	for index := 1; index <= 10_000; index++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, index, extension)
		if _, err := s.files.Metadata(ctx, mountID, candidate); errors.Is(err, filesystem.ErrNotFound) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("%w: could not find an available conflict name", ErrInvalid)
}

func normalizeConflictPolicy(policy string, overwrite bool) (string, error) {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		if overwrite {
			return "overwrite", nil
		}
		return "fail", nil
	}
	switch policy {
	case "skip", "overwrite", "rename", "fail", "ask", "checksum":
		return policy, nil
	default:
		return "", fmt.Errorf("%w: conflict_policy must be skip, overwrite, rename, fail, ask, or checksum", ErrInvalid)
	}
}

func normalizeSourceChangePolicy(policy string) (string, error) {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		return "fail", nil
	}
	switch policy {
	case "fail", "retry", "copy_anyway":
		return policy, nil
	default:
		return "", fmt.Errorf("%w: source_change_policy must be fail, retry, or copy_anyway", ErrInvalid)
	}
}

func joinRelative(base, relative string) string {
	if relative == "" || relative == "." {
		return strings.TrimPrefix(path.Clean(base), "./")
	}
	if base == "" || base == "." {
		return strings.TrimPrefix(path.Clean(relative), "./")
	}
	return strings.TrimPrefix(path.Join(base, relative), "./")
}

func (s *Service) Pause(ctx context.Context, id string) (entities.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.getForUpdate(ctx, id)
	if err != nil {
		return job, err
	}
	switch job.State {
	case "queued", "interrupted", "waiting_peer", "waiting_mount", "waiting_validation":
		job.State, job.Phase = "paused", "paused"
	case "running":
		if !s.interruptible(ctx, job) {
			return job, fmt.Errorf("%w: running %s jobs cannot be paused safely", ErrInvalidState, job.Type)
		}
		job.State, job.Phase = "pause_requested", "pausing"
		if cancel := s.running[id]; cancel != nil {
			cancel()
		}
	case "paused":
		return job, nil
	default:
		return job, fmt.Errorf("%w: cannot pause job in %s", ErrInvalidState, job.State)
	}
	job.UpdatedAt = s.now()
	if err := s.store.UpdateJob(ctx, job); err != nil {
		return job, err
	}
	s.recordEvent(ctx, job, "job."+job.State, "")
	return job, nil
}

func (s *Service) Resume(ctx context.Context, id string) (entities.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.getForUpdate(ctx, id)
	if err != nil {
		return job, err
	}
	if job.State != "paused" && job.State != "interrupted" && job.State != "waiting_validation" {
		return job, fmt.Errorf("%w: cannot resume job in %s", ErrInvalidState, job.State)
	}
	job.State, job.Phase, job.Error = "queued", "validation", ""
	job.UpdatedAt, job.NextAttemptAt, job.CompletedAt = s.now(), nil, nil
	if err := s.store.UpdateJob(ctx, job); err != nil {
		return job, err
	}
	s.recordEvent(ctx, job, "job.resumed", "")
	s.notify()
	return job, nil
}

func (s *Service) WakePeer(ctx context.Context, peerNodeID string) (int, error) {
	items, err := s.store.WakeWaitingPeerJobs(ctx, peerNodeID, s.now())
	if err != nil {
		return 0, err
	}
	for _, job := range items {
		s.recordEvent(ctx, job, "job.peer_available", "authenticated heartbeat confirmed the peer is online")
	}
	if len(items) > 0 {
		s.notify()
	}
	return len(items), nil
}

func (s *Service) CancelPeer(ctx context.Context, peerNodeID string) (int, error) {
	items, err := s.store.ListJobsByPeer(ctx, peerNodeID)
	if err != nil {
		return 0, err
	}
	canceled := 0
	for _, job := range items {
		switch job.State {
		case "queued", "paused", "interrupted", "waiting_peer", "waiting_mount",
			"waiting_validation", "waiting_user_decision", "running", "pause_requested":
			if _, err := s.Cancel(ctx, job.ID); err != nil {
				return canceled, err
			}
			canceled++
		}
	}
	return canceled, nil
}

func (s *Service) WakeMount(ctx context.Context, mountID string) (int, error) {
	mount, err := s.files.GetMount(ctx, mountID)
	if errors.Is(err, filesystem.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !mountReady(mount) {
		return 0, nil
	}
	items, err := s.store.WakeWaitingMountJobs(ctx, mountID, s.now())
	if err != nil {
		return 0, err
	}
	for _, job := range items {
		s.recordEvent(ctx, job, "job.mount_available", "mount diagnostics passed; job returned to validation")
	}
	if len(items) > 0 {
		s.notify()
	}
	return len(items), nil
}

func (s *Service) Cancel(ctx context.Context, id string) (entities.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.getForUpdate(ctx, id)
	if err != nil {
		return job, err
	}
	now := s.now()
	switch job.State {
	case "queued", "paused", "interrupted", "waiting_peer", "waiting_mount", "waiting_validation", "waiting_user_decision":
		job.State, job.Phase, job.CompletedAt = "canceled", "cleanup", &now
	case "running", "pause_requested":
		if !s.interruptible(ctx, job) {
			return job, fmt.Errorf("%w: running %s jobs cannot be canceled safely", ErrInvalidState, job.Type)
		}
		job.State, job.Phase = "cancel_requested", "canceling"
		if cancel := s.running[id]; cancel != nil {
			cancel()
		}
	case "canceled":
		return job, nil
	default:
		return job, fmt.Errorf("%w: cannot cancel job in %s", ErrInvalidState, job.State)
	}
	job.UpdatedAt = now
	if err := s.store.UpdateJob(ctx, job); err != nil {
		return job, err
	}
	s.recordEvent(ctx, job, "job."+job.State, "")
	if job.State == "canceled" {
		s.cleanupJobPartials(ctx, job)
	}
	return job, nil
}

func (s *Service) interruptible(ctx context.Context, job entities.Job) bool {
	return job.Type == "copy_local" || job.Type == "transfer_pull" || job.Type == "transfer_pull_directory"
}

func (s *Service) Retry(ctx context.Context, id string) (entities.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.getForUpdate(ctx, id)
	if err != nil {
		return job, err
	}
	if job.State != "failed" && job.State != "completed_with_warnings" {
		return job, fmt.Errorf("%w: cannot retry job in %s", ErrInvalidState, job.State)
	}
	job.State, job.Phase, job.Error = "queued", "validation", ""
	job.Attempt = 0
	job.UpdatedAt, job.NextAttemptAt, job.CompletedAt = s.now(), nil, nil
	if err := s.store.UpdateJob(ctx, job); err != nil {
		return job, err
	}
	s.recordEvent(ctx, job, "job.retry_requested", "")
	s.notify()
	return job, nil
}

func (s *Service) OverrideItem(ctx context.Context, id string, ordinal int, action string, applyToFollowing bool) (entities.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.getForUpdate(ctx, id)
	if err != nil {
		return job, err
	}
	if job.State != "waiting_user_decision" {
		return job, fmt.Errorf("%w: job is not waiting for a decision", ErrInvalidState)
	}
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "skip", "overwrite", "rename", "fail":
	default:
		return job, fmt.Errorf("%w: override action must be skip, overwrite, rename, or fail", ErrInvalid)
	}
	items, err := s.store.ListJobItems(ctx, id)
	if err != nil {
		return job, err
	}
	found := false
	targets := make([]int, 0)
	for index := range items {
		item := &items[index]
		if item.Ordinal != ordinal && !(applyToFollowing && item.Ordinal > ordinal && item.Action == "conflict") {
			continue
		}
		if item.Ordinal == ordinal {
			found = true
			if item.Action != "conflict" {
				return job, fmt.Errorf("%w: item is not an unresolved conflict", ErrInvalidState)
			}
		}
		if item.Action != "conflict" {
			continue
		}
		if item.Type != "file" && (action == "overwrite" || action == "rename") {
			return job, fmt.Errorf("%w: directory conflicts only support skip or fail overrides", ErrInvalid)
		}
		targets = append(targets, index)
		if action == "rename" {
			item.DestinationPath, err = s.uniqueDestination(ctx, job.MountID, item.DestinationPath)
			if err != nil {
				return job, err
			}
		}
	}
	if !found {
		return job, ErrNotFound
	}
	for _, index := range targets {
		item := &items[index]
		item.Action, item.State, item.Error, item.UpdatedAt = action, "pending", "", s.now()
		if err := s.store.UpdateJobItem(ctx, *item); err != nil {
			return job, err
		}
	}
	unresolved := false
	for _, item := range items {
		if item.Action == "conflict" {
			unresolved = true
			break
		}
	}
	job.UpdatedAt = s.now()
	if !unresolved {
		job.State, job.Phase, job.Error = "queued", "validation", ""
		job.NextAttemptAt, job.CompletedAt = nil, nil
	}
	if err := s.store.UpdateJob(ctx, job); err != nil {
		return job, err
	}
	s.recordEvent(ctx, job, "job.override_applied", fmt.Sprintf("override %s applied to item %d", action, ordinal))
	if !unresolved {
		s.notify()
	}
	return job, nil
}

func (s *Service) getForUpdate(ctx context.Context, id string) (entities.Job, error) {
	job, err := s.store.GetJob(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return job, ErrNotFound
	}
	return job, err
}

func (s *Service) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Service) worker() {
	defer s.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
		for {
			job, err := s.store.ClaimNextJob(s.ctx, s.now())
			if errors.Is(err, db.ErrNotFound) {
				break
			}
			if err != nil {
				break
			}
			s.execute(job)
			if s.ctx.Err() != nil {
				return
			}
		}
	}
}

func (s *Service) mountMonitor() {
	defer s.wg.Done()
	s.checkMounts()
	ticker := time.NewTicker(s.mountCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkMounts()
		}
	}
}

func (s *Service) checkMounts() {
	mounts, err := s.files.ListMounts(s.ctx)
	if err != nil {
		return
	}
	for _, mount := range mounts {
		if s.ctx.Err() != nil {
			return
		}
		if mountReady(mount) {
			_, _ = s.WakeMount(s.ctx, mount.ID)
		}
	}
}

func (s *Service) execute(job entities.Job) {
	ctx, cancel := context.WithCancel(s.ctx)
	s.mu.Lock()
	s.running[job.ID] = cancel
	current, err := s.store.GetJob(ctx, job.ID)
	if err == nil && current.State == "running" {
		job = current
		s.recordEvent(ctx, job, "job.validating", "validating mount before execution")
		validationCtx, validationCancel := context.WithTimeout(ctx, s.validationTimeout)
		validationErr := s.validateMount(validationCtx, job)
		if errors.Is(validationErr, context.DeadlineExceeded) {
			validationErr = ErrValidationTimeout
		}
		validationCancel()
		if validationErr != nil {
			err = validationErr
		} else {
			job.Phase, job.UpdatedAt = "transfer", s.now()
			err = s.store.UpdateJob(ctx, job)
			if err == nil {
				s.recordEvent(ctx, job, "job.started", "")
			}
		}
	}
	s.mu.Unlock()

	// A control request can race with the worker claim. Re-read and update the
	// durable state while holding the same lock used by control operations.
	if err == nil && current.State != "running" {
		cancel()
		s.finish(current, context.Canceled, 0)
	} else if err != nil {
		s.finish(job, err, 0)
	} else {
		operationCtx, operationCancel := context.WithCancelCause(ctx)
		progress := make(chan struct{}, 1)
		s.mu.Lock()
		s.progress[job.ID] = progress
		if job.BandwidthLimit > 0 {
			s.jobBandwidth[job.ID] = newByteRateLimiter(job.BandwidthLimit)
		}
		s.mu.Unlock()
		watchDone := make(chan struct{})
		chunked := job.Type == "copy_local" || job.Type == "transfer_pull" || job.Type == "transfer_pull_directory"
		go s.watchProgress(operationCtx, operationCancel, progress, watchDone, chunked)
		bytes, operationErr := s.executeOperation(operationCtx, job)
		operationCancel(nil)
		<-watchDone
		s.mu.Lock()
		delete(s.progress, job.ID)
		delete(s.jobBandwidth, job.ID)
		s.mu.Unlock()
		if cause := context.Cause(operationCtx); cause != nil &&
			errors.Is(operationErr, context.Canceled) && !errors.Is(cause, context.Canceled) {
			operationErr = cause
		}
		if operationErr != nil {
			operationErr = s.classifyMountFailure(ctx, job, operationErr)
		}
		s.finish(job, operationErr, bytes)
	}

	s.mu.Lock()
	delete(s.running, job.ID)
	s.mu.Unlock()
	cancel()
}

func (s *Service) BandwidthLimiter(job entities.Job) filesystem.ByteRateLimiter {
	jobID := job.ID
	if job.ParentJobID != "" {
		jobID = job.ParentJobID
	}
	s.mu.Lock()
	jobLimiter := s.jobBandwidth[jobID]
	if jobLimiter == nil && job.BandwidthLimit > 0 {
		jobLimiter = newByteRateLimiter(job.BandwidthLimit)
		s.jobBandwidth[jobID] = jobLimiter
	}
	s.mu.Unlock()
	var limiter filesystem.ByteRateLimiter
	if s.nodeBandwidth == nil {
		limiter = jobLimiter
	} else if jobLimiter == nil {
		limiter = s.nodeBandwidth
	} else {
		limiter = combinedRateLimiter{s.nodeBandwidth, jobLimiter}
	}
	if limiter == nil {
		return nil
	}
	interval := minDuration(s.chunkTimeout, s.noProgressTimeout) / 2
	if interval > time.Second {
		interval = time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	return progressRateLimiter{limiter: limiter, interval: interval, progress: func() {
		s.signalProgress(jobID)
	}}
}

func (s *Service) ReleaseBandwidthLimiter(jobID string) {
	s.mu.Lock()
	delete(s.jobBandwidth, jobID)
	s.mu.Unlock()
}

type byteRateLimiter struct {
	mu             sync.Mutex
	bytesPerSecond int64
	next           time.Time
}

func newByteRateLimiter(bytesPerSecond int64) *byteRateLimiter {
	return &byteRateLimiter{bytesPerSecond: bytesPerSecond}
}

func (l *byteRateLimiter) Wait(ctx context.Context, bytes int64) error {
	if l == nil || l.bytesPerSecond <= 0 || bytes <= 0 {
		return nil
	}
	duration := time.Duration(float64(bytes) / float64(l.bytesPerSecond) * float64(time.Second))
	if duration <= 0 {
		return nil
	}
	now := time.Now()
	l.mu.Lock()
	start := now
	if l.next.After(start) {
		start = l.next
	}
	l.next = start.Add(duration)
	delay := l.next.Sub(now)
	l.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type combinedRateLimiter [2]filesystem.ByteRateLimiter

func (l combinedRateLimiter) Wait(ctx context.Context, bytes int64) error {
	waitContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(l))
	for _, limiter := range l {
		go func(current filesystem.ByteRateLimiter) {
			results <- current.Wait(waitContext, bytes)
		}(limiter)
	}
	for range l {
		if err := <-results; err != nil {
			cancel()
			return err
		}
	}
	return nil
}

type progressRateLimiter struct {
	limiter  filesystem.ByteRateLimiter
	interval time.Duration
	progress func()
}

func (l progressRateLimiter) Wait(ctx context.Context, bytes int64) error {
	result := make(chan error, 1)
	go func() {
		result <- l.limiter.Wait(ctx, bytes)
	}()
	ticker := time.NewTicker(l.interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-result:
			return err
		case <-ticker.C:
			l.progress()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func (s *Service) watchProgress(ctx context.Context, cancel context.CancelCauseFunc, progress <-chan struct{}, done chan<- struct{}, chunked bool) {
	defer close(done)
	noProgressTimer := time.NewTimer(s.noProgressTimeout)
	defer noProgressTimer.Stop()
	var chunkTimer *time.Timer
	var chunkDeadline <-chan time.Time
	if chunked {
		chunkTimer = time.NewTimer(s.chunkTimeout)
		chunkDeadline = chunkTimer.C
		defer chunkTimer.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-progress:
			if !noProgressTimer.Stop() {
				select {
				case <-noProgressTimer.C:
				default:
				}
			}
			noProgressTimer.Reset(s.noProgressTimeout)
			if chunkTimer != nil {
				if !chunkTimer.Stop() {
					select {
					case <-chunkTimer.C:
					default:
					}
				}
				chunkTimer.Reset(s.chunkTimeout)
				chunkDeadline = chunkTimer.C
			}
		case <-chunkDeadline:
			cancel(ErrChunkTimeout)
			return
		case <-noProgressTimer.C:
			cancel(ErrNoProgress)
			return
		}
	}
}

func (s *Service) signalProgress(id string) {
	s.mu.Lock()
	progress := s.progress[id]
	s.mu.Unlock()
	if progress != nil {
		select {
		case progress <- struct{}{}:
		default:
		}
	}
}

func (s *Service) validateMount(ctx context.Context, job entities.Job) error {
	mount, err := s.files.GetMount(ctx, job.MountID)
	if errors.Is(err, filesystem.ErrNotFound) {
		return fmt.Errorf("%w: mount %s is missing", ErrWaitingMount, job.MountID)
	}
	if err != nil {
		return err
	}
	if !mountReady(mount) {
		return fmt.Errorf("%w: mount %s is %s (enabled=%t readable=%t writable=%t)",
			ErrWaitingMount, job.MountID, mount.State, mount.Enabled, mount.Readable, mount.Writable)
	}
	return nil
}

func (s *Service) classifyMountFailure(ctx context.Context, job entities.Job, operationErr error) error {
	if errors.Is(operationErr, filesystem.ErrDisabled) {
		return fmt.Errorf("%w: %v", ErrWaitingMount, operationErr)
	}
	mount, err := s.files.GetMount(ctx, job.MountID)
	if errors.Is(err, filesystem.ErrNotFound) || (err == nil && !mountReady(mount)) {
		return fmt.Errorf("%w: mount became unavailable: %v", ErrWaitingMount, operationErr)
	}
	return operationErr
}

func mountReady(mount entities.Mount) bool {
	return mount.Enabled && mount.State == "available" && mount.Readable && mount.Writable
}

func (s *Service) executeOperation(ctx context.Context, job entities.Job) (int64, error) {
	switch job.Type {
	case "mkdir":
		return 0, s.files.CreateDirectory(ctx, job.MountID, job.Destination)
	case "copy_local":
		return s.executeCopy(ctx, job)
	case "transfer_pull":
		if s.remote == nil {
			return 0, errors.New("remote transfer executor is unavailable")
		}
		return s.remote.ExecutePull(ctx, job, func(completed, total int64) error {
			return s.checkpointProgress(job.ID, completed, total)
		})
	case "transfer_pull_directory":
		if s.remote == nil {
			return 0, errors.New("remote transfer executor is unavailable")
		}
		return s.remote.ExecuteDirectoryPull(ctx, job, func(completed, total int64, filesCompleted, filesFailed int) error {
			return s.checkpointDirectoryProgress(job.ID, completed, total, filesCompleted, filesFailed)
		})
	case "move_local":
		return 0, s.files.Move(ctx, job.MountID, job.SourcePath, job.Destination, job.Overwrite)
	case "delete":
		return 0, s.files.Delete(ctx, job.MountID, job.SourcePath, job.Recursive)
	default:
		return 0, fmt.Errorf("unsupported queued job type %q", job.Type)
	}
}

func (s *Service) executeCopy(ctx context.Context, job entities.Job) (int64, error) {
	items, err := s.store.ListJobItems(ctx, job.ID)
	if err != nil {
		return 0, err
	}
	if len(items) == 0 {
		job.Phase, job.UpdatedAt = "planning", s.now()
		if err := s.store.UpdateJob(ctx, job); err != nil {
			return 0, err
		}
		s.recordEvent(ctx, job, "job.planning", "")
		plan, err := s.PlanCopy(ctx, job.MountID, job.SourcePath, job.Destination, job.ConflictPolicy, job.VerifyChecksum)
		if err != nil {
			return 0, err
		}
		for index := range plan.Items {
			plan.Items[index].JobID = job.ID
		}
		if err := s.store.ReplaceJobItems(ctx, job.ID, plan.Items); err != nil {
			return 0, err
		}
		job.BytesTotal, job.FilesTotal = plan.BytesTotal, plan.FilesTotal
		job.Phase, job.UpdatedAt = "transfer", s.now()
		if err := s.store.UpdateJob(ctx, job); err != nil {
			return 0, err
		}
		s.recordEvent(ctx, job, "job.planned", "")
		items = plan.Items
	}
	if job.MaxParallelFiles > 1 && parallelLocalCopyEligible(items) {
		return s.executeParallelLocalCopy(ctx, job, items)
	}

	var bytesCompleted int64
	var filesCompleted, filesFailed int
	var warningItems int
	for _, item := range items {
		if item.Type != "file" {
			continue
		}
		switch item.State {
		case "completed":
			bytesCompleted += item.BytesCompleted
			filesCompleted++
		case "skipped":
			filesCompleted++
		}
	}
	for _, item := range items {
		if item.Type == "file" {
			switch item.State {
			case "completed", "skipped":
				continue
			}
		} else if item.State == "completed" || item.State == "skipped" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return bytesCompleted, err
		}
		item.JobID = job.ID
		item.Attempt++
		item.UpdatedAt, item.Error = s.now(), ""
		if item.State == "failed" {
			action, destination, checksum, planErr := s.planAction(ctx, job.MountID, item, job.ConflictPolicy)
			if planErr != nil {
				return bytesCompleted, planErr
			}
			item.Action, item.DestinationPath, item.Checksum = action, destination, checksum
		}
		switch item.Action {
		case "skip":
			item.State = "skipped"
			if item.Type == "file" {
				filesCompleted++
			}
		case "conflict":
			if job.ConflictPolicy == "ask" {
				item.State, item.Error, item.UpdatedAt = "waiting_user_decision", "destination conflict requires a decision", s.now()
				if err := s.store.UpdateJobItem(ctx, item); err != nil {
					return bytesCompleted, err
				}
				return bytesCompleted, ErrWaitingUserDecision
			}
			item.State, item.Error = "failed", "destination conflict"
			warningItems++
			if item.Type == "file" {
				filesFailed++
			}
		case "fail":
			item.State, item.Error = "failed", "destination conflict rejected by user"
			warningItems++
			if item.Type == "file" {
				filesFailed++
			}
		case "merge":
			item.State = "completed"
		case "create":
			if err := s.files.CreateDirectory(ctx, job.MountID, item.DestinationPath); err != nil {
				item.State, item.Error = "failed", err.Error()
				_ = s.store.UpdateJobItem(context.Background(), item)
				return bytesCompleted, err
			}
			item.State = "completed"
		case "copy", "overwrite", "rename":
			current, metadataErr := s.files.Metadata(ctx, job.MountID, item.SourcePath)
			if metadataErr != nil {
				item.State, item.Error, item.UpdatedAt = "failed", metadataErr.Error(), s.now()
				_ = s.store.UpdateJobItem(context.Background(), item)
				return bytesCompleted, metadataErr
			}
			sourceChanged := current.Size != item.Size || !current.ModifiedAt.Equal(item.ModifiedAt)
			if sourceChanged && job.SourceChangePolicy != "copy_anyway" {
				item.Error, item.UpdatedAt = "source changed after the manifest was created", s.now()
				if job.SourceChangePolicy == "retry" {
					item.Size, item.ModifiedAt, item.State = current.Size, current.ModifiedAt, "pending"
					if job.VerifyChecksum {
						item.Checksum, metadataErr = s.files.Checksum(ctx, job.MountID, item.SourcePath)
						if metadataErr != nil {
							return bytesCompleted, metadataErr
						}
					}
					if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
						return bytesCompleted, err
					}
					return bytesCompleted, errors.New("source changed; retrying with refreshed metadata")
				}
				item.State = "failed"
				warningItems++
				filesFailed++
				if err := s.store.UpdateJobItem(ctx, item); err != nil {
					return bytesCompleted, err
				}
				continue
			}
			if sourceChanged {
				item.Size, item.ModifiedAt = current.Size, current.ModifiedAt
			}
			if job.VerifyChecksum && item.Checksum == "" {
				item.Checksum, metadataErr = s.files.Checksum(ctx, job.MountID, item.SourcePath)
				if metadataErr != nil {
					return bytesCompleted, metadataErr
				}
			}
			item.State = "running"
			if err := s.store.UpdateJobItem(ctx, item); err != nil {
				return bytesCompleted, err
			}
			base := bytesCompleted
			progress := func(completed, _ int64) error {
				now := s.now()
				item.BytesCompleted, item.UpdatedAt = completed, now
				if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
					return err
				}
				s.updateDirectoryProgress(job.ID, base+completed, job.BytesTotal, filesCompleted, filesFailed, now)
				return nil
			}
			var written int64
			var copiedChecksum string
			written, copiedChecksum, copyErr := s.files.CopyFileResumableParallel(ctx, job.MountID,
				item.SourcePath, item.DestinationPath, fmt.Sprintf("%s-%d", job.ID, item.Ordinal),
				item.Action == "overwrite", item.BytesCompleted, s.chunkSize, job.MaxParallelChunks, item.Checksum,
				job.SourceChangePolicy == "copy_anyway", progress, s.BandwidthLimiter(job))
			if copyErr != nil {
				if errors.Is(copyErr, filesystem.ErrSourceChanged) && job.SourceChangePolicy == "retry" {
					refreshed, refreshErr := s.files.Metadata(ctx, job.MountID, item.SourcePath)
					if refreshErr != nil {
						return bytesCompleted, refreshErr
					}
					item.Size, item.ModifiedAt, item.State = refreshed.Size, refreshed.ModifiedAt, "pending"
					item.Checksum, refreshErr = s.files.Checksum(ctx, job.MountID, item.SourcePath)
					if refreshErr != nil {
						return bytesCompleted, refreshErr
					}
					item.Error, item.UpdatedAt = copyErr.Error(), s.now()
					if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
						return bytesCompleted, err
					}
					return bytesCompleted, copyErr
				}
				if errors.Is(copyErr, filesystem.ErrSourceChanged) && job.SourceChangePolicy == "fail" {
					item.State, item.Error, item.UpdatedAt = "failed", copyErr.Error(), s.now()
					warningItems++
					filesFailed++
					if err := s.store.UpdateJobItem(ctx, item); err != nil {
						return bytesCompleted, err
					}
					continue
				}
				item.State, item.UpdatedAt = "pending", s.now()
				if !errors.Is(copyErr, context.Canceled) {
					item.State, item.Error = "failed", copyErr.Error()
				}
				_ = s.store.UpdateJobItem(context.Background(), item)
				return bytesCompleted, copyErr
			}
			if job.VerifyChecksum {
				item.Checksum = copiedChecksum
			}
			item.State, item.BytesCompleted, item.UpdatedAt = "completed", written, s.now()
			bytesCompleted += written
			filesCompleted++
		default:
			return bytesCompleted, fmt.Errorf("%w: unsupported plan action %q", ErrInvalid, item.Action)
		}
		if err := s.store.UpdateJobItem(ctx, item); err != nil {
			return bytesCompleted, err
		}
		s.updateDirectoryProgress(job.ID, bytesCompleted, job.BytesTotal, filesCompleted, filesFailed, s.now())
	}
	s.updateDirectoryProgress(job.ID, bytesCompleted, job.BytesTotal, filesCompleted, filesFailed, s.now())
	if warningItems > 0 {
		return bytesCompleted, fmt.Errorf("%w: %d item(s) could not be copied", ErrWarnings, warningItems)
	}
	return bytesCompleted, nil
}

func parallelLocalCopyEligible(items []entities.JobItem) bool {
	for _, item := range items {
		if item.State == "completed" || item.State == "skipped" {
			continue
		}
		if item.State == "failed" {
			return false
		}
		if item.Type == "directory" {
			if item.Action != "create" && item.Action != "merge" {
				return false
			}
			continue
		}
		if item.Action != "copy" && item.Action != "overwrite" && item.Action != "rename" {
			return false
		}
	}
	return true
}

func (s *Service) executeParallelLocalCopy(ctx context.Context, job entities.Job, items []entities.JobItem) (int64, error) {
	var stateMu sync.Mutex
	var bytesCompleted int64
	var filesCompleted, filesFailed int
	var pendingFiles []entities.JobItem
	for _, item := range items {
		if item.Type == "file" {
			bytesCompleted += item.BytesCompleted
			if item.State == "completed" || item.State == "skipped" {
				filesCompleted++
			}
		}
	}
	for _, item := range items {
		if item.State == "completed" || item.State == "skipped" {
			continue
		}
		item.JobID, item.Attempt, item.UpdatedAt, item.Error = job.ID, item.Attempt+1, s.now(), ""
		if item.Type == "file" {
			pendingFiles = append(pendingFiles, item)
			continue
		}
		if item.Action == "create" {
			if err := s.files.CreateDirectory(ctx, job.MountID, item.DestinationPath); err != nil {
				item.State, item.Error = "failed", err.Error()
				_ = s.store.UpdateJobItem(context.Background(), item)
				return bytesCompleted, err
			}
		}
		item.State = "completed"
		if err := s.store.UpdateJobItem(ctx, item); err != nil {
			return bytesCompleted, err
		}
	}
	parallelism := min(job.MaxParallelFiles, len(pendingFiles))
	if parallelism == 0 {
		return bytesCompleted, nil
	}
	workContext, cancel := context.WithCancel(ctx)
	defer cancel()
	queue := make(chan entities.JobItem, len(pendingFiles))
	results := make(chan error, len(pendingFiles))
	for _, item := range pendingFiles {
		queue <- item
	}
	close(queue)
	for range parallelism {
		go func() {
			for item := range queue {
				current, metadataErr := s.files.Metadata(workContext, job.MountID, item.SourcePath)
				if metadataErr != nil {
					item.State, item.Error, item.UpdatedAt = "failed", metadataErr.Error(), s.now()
					_ = s.store.UpdateJobItem(context.Background(), item)
					results <- metadataErr
					continue
				}
				sourceChanged := current.Size != item.Size || !current.ModifiedAt.Equal(item.ModifiedAt)
				if sourceChanged && job.SourceChangePolicy != "copy_anyway" {
					item.Error, item.UpdatedAt = "source changed after the manifest was created", s.now()
					if job.SourceChangePolicy == "retry" {
						item.Size, item.ModifiedAt, item.State = current.Size, current.ModifiedAt, "pending"
						if job.VerifyChecksum {
							item.Checksum, metadataErr = s.files.Checksum(workContext, job.MountID, item.SourcePath)
						}
						_ = s.store.UpdateJobItem(context.Background(), item)
						if metadataErr != nil {
							results <- metadataErr
						} else {
							results <- filesystem.ErrSourceChanged
						}
						continue
					}
					item.State = "failed"
					stateMu.Lock()
					filesFailed++
					stateMu.Unlock()
					_ = s.store.UpdateJobItem(context.Background(), item)
					results <- nil
					continue
				}
				if sourceChanged {
					item.Size, item.ModifiedAt = current.Size, current.ModifiedAt
				}
				if job.VerifyChecksum && item.Checksum == "" {
					item.Checksum, metadataErr = s.files.Checksum(workContext, job.MountID, item.SourcePath)
					if metadataErr != nil {
						results <- metadataErr
						continue
					}
				}
				item.State = "running"
				if err := s.store.UpdateJobItem(workContext, item); err != nil {
					results <- err
					continue
				}
				written, checksum, copyErr := s.files.CopyFileResumableParallel(workContext, job.MountID,
					item.SourcePath, item.DestinationPath, fmt.Sprintf("%s-%d", job.ID, item.Ordinal),
					item.Action == "overwrite", item.BytesCompleted, s.chunkSize, job.MaxParallelChunks, item.Checksum,
					job.SourceChangePolicy == "copy_anyway", func(completed, _ int64) error {
						stateMu.Lock()
						bytesCompleted += completed - item.BytesCompleted
						item.BytesCompleted, item.UpdatedAt = completed, s.now()
						currentBytes, currentCompleted, currentFailed := bytesCompleted, filesCompleted, filesFailed
						stateMu.Unlock()
						if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
							return err
						}
						s.updateDirectoryProgress(job.ID, currentBytes, job.BytesTotal, currentCompleted, currentFailed, s.now())
						return nil
					}, s.BandwidthLimiter(job))
				if copyErr != nil {
					item.UpdatedAt = s.now()
					if errors.Is(copyErr, context.Canceled) {
						item.State, item.Error = "pending", ""
					} else {
						item.State, item.Error = "failed", copyErr.Error()
					}
					_ = s.store.UpdateJobItem(context.Background(), item)
					results <- copyErr
					continue
				}
				stateMu.Lock()
				bytesCompleted += written - item.BytesCompleted
				item.State, item.BytesCompleted, item.UpdatedAt = "completed", written, s.now()
				if job.VerifyChecksum {
					item.Checksum = checksum
				}
				filesCompleted++
				currentBytes, currentCompleted, currentFailed := bytesCompleted, filesCompleted, filesFailed
				stateMu.Unlock()
				if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
					results <- err
					continue
				}
				s.updateDirectoryProgress(job.ID, currentBytes, job.BytesTotal, currentCompleted, currentFailed, s.now())
				results <- nil
			}
		}()
	}
	var firstErr error
	for range pendingFiles {
		if resultErr := <-results; resultErr != nil && firstErr == nil {
			firstErr = resultErr
			cancel()
		}
	}
	stateMu.Lock()
	completed, failed := bytesCompleted, filesFailed
	stateMu.Unlock()
	if firstErr != nil {
		return completed, firstErr
	}
	if failed > 0 {
		return completed, fmt.Errorf("%w: %d item(s) could not be copied", ErrWarnings, failed)
	}
	return completed, nil
}

func (s *Service) updateDirectoryProgress(id string, completed, total int64, filesCompleted, filesFailed int, now time.Time) {
	s.signalProgress(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.store.GetJob(context.Background(), id)
	if err != nil || job.State != "running" {
		return
	}
	job.FilesCompleted, job.FilesFailed = filesCompleted, filesFailed
	s.applyByteProgress(&job, completed, total, now)
	if err := s.store.UpdateJob(context.Background(), job); err == nil {
		s.recordEvent(context.Background(), job, "job.progress", "")
	}
}

func (s *Service) updateProgress(id string, completed, total int64, now time.Time) {
	s.signalProgress(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.store.GetJob(context.Background(), id)
	if err != nil || job.State != "running" {
		return
	}
	s.applyByteProgress(&job, completed, total, now)
	if err := s.store.UpdateJob(context.Background(), job); err == nil {
		s.recordEvent(context.Background(), job, "job.progress", "")
	}
}

func (s *Service) checkpointProgress(id string, completed, total int64) error {
	s.signalProgress(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.store.GetJob(context.Background(), id)
	if err != nil {
		return err
	}
	if job.State != "running" {
		return context.Canceled
	}
	s.applyByteProgress(&job, completed, total, s.now())
	if err := s.store.UpdateJob(context.Background(), job); err != nil {
		return err
	}
	s.recordEvent(context.Background(), job, "job.progress", "")
	return nil
}

func (s *Service) checkpointDirectoryProgress(id string, completed, total int64, filesCompleted, filesFailed int) error {
	s.signalProgress(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.store.GetJob(context.Background(), id)
	if err != nil {
		return err
	}
	if job.State != "running" {
		return context.Canceled
	}
	job.FilesCompleted, job.FilesFailed = filesCompleted, filesFailed
	s.applyByteProgress(&job, completed, total, s.now())
	if err := s.store.UpdateJob(context.Background(), job); err != nil {
		return err
	}
	s.recordEvent(context.Background(), job, "job.progress", "")
	return nil
}

func (s *Service) applyByteProgress(job *entities.Job, completed, total int64, now time.Time) {
	job.BytesCompleted, job.BytesTotal, job.UpdatedAt = completed, total, now
	if job.StartedAt != nil && completed > 0 {
		elapsed := now.Sub(*job.StartedAt).Seconds()
		if elapsed > 0 {
			job.BytesPerSecond = float64(completed) / elapsed
			if total > completed && job.BytesPerSecond > 0 {
				eta := int64(math.Ceil(float64(total-completed) / job.BytesPerSecond))
				job.ETASeconds = &eta
				job.ETAConfidence = etaConfidence(elapsed, completed, total)
			} else {
				eta := int64(0)
				job.ETASeconds, job.ETAConfidence = &eta, "high"
			}
		}
	}
}

func (s *Service) finish(job entities.Job, operationErr error, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()
	current, err := s.store.GetJob(ctx, job.ID)
	if err != nil {
		return
	}
	now := s.now()
	current.UpdatedAt = now
	eventType := ""
	switch current.State {
	case "pause_requested":
		current.State, current.Phase, current.Error = "paused", "paused", ""
		eventType = "job.paused"
	case "cancel_requested":
		current.State, current.Phase, current.Error, current.CompletedAt = "canceled", "cleanup", "", &now
		eventType = "job.canceled"
	default:
		if s.ctx.Err() != nil && errors.Is(operationErr, context.Canceled) {
			current.State, current.Phase = "waiting_validation", "waiting_validation"
			current.Error = "node stopped before the operation completed; explicit validation is required"
			eventType = "job.interrupted"
		} else if operationErr == nil {
			current.State, current.Phase, current.Error, current.CompletedAt = "completed", "finalization", "", &now
			current.BytesCompleted, current.BytesTotal = bytes, bytes
			eventType = "job.completed"
		} else if errors.Is(operationErr, ErrWarnings) {
			current.State, current.Phase, current.Error, current.CompletedAt = "completed_with_warnings", "finalization", operationErr.Error(), &now
			current.BytesCompleted = bytes
			eventType = "job.completed_with_warnings"
		} else if errors.Is(operationErr, ErrWaitingUserDecision) {
			current.State, current.Phase, current.Error = "waiting_user_decision", "waiting_user_decision", operationErr.Error()
			eventType = "job.waiting_user_decision"
		} else if errors.Is(operationErr, ErrWaitingPeer) {
			current.State, current.Phase, current.Error, current.NextAttemptAt = "waiting_peer", "waiting_peer", operationErr.Error(), nil
			if current.Attempt > 0 {
				current.Attempt--
			}
			eventType = "job.waiting_peer"
		} else if errors.Is(operationErr, ErrWaitingMount) {
			current.State, current.Phase, current.Error, current.NextAttemptAt = "waiting_mount", "waiting_mount", operationErr.Error(), nil
			if current.Attempt > 0 {
				current.Attempt--
			}
			eventType = "job.waiting_mount"
		} else if current.Attempt < current.MaxAttempts {
			delay := time.Second << min(current.Attempt-1, 6)
			next := now.Add(delay)
			current.State, current.Phase, current.Error, current.NextAttemptAt = "queued", "retry_wait", operationErr.Error(), &next
			eventType = "job.retry_scheduled"
		} else {
			current.State, current.Phase, current.Error, current.CompletedAt = "failed", "finalization", operationErr.Error(), &now
			eventType = "job.failed"
		}
	}
	current.ETASeconds, current.ETAConfidence = nil, ""
	if err := s.store.UpdateJob(ctx, current); err == nil {
		s.recordEvent(ctx, current, eventType, current.Error)
		if current.State == "canceled" {
			s.cleanupJobPartials(ctx, current)
		}
	}
}

func (s *Service) cleanupJobPartials(ctx context.Context, job entities.Job) {
	if job.Type == "transfer_pull" && s.remote != nil {
		_ = s.remote.CleanupPull(ctx, job)
		return
	}
	if job.Type == "transfer_pull_directory" && s.remote != nil {
		_ = s.remote.CleanupDirectoryPull(ctx, job)
		return
	}
	if job.Type != "copy_local" {
		return
	}
	items, err := s.store.ListJobItems(ctx, job.ID)
	if err != nil {
		return
	}
	for _, item := range items {
		if item.Type != "file" || item.State == "completed" || item.State == "skipped" {
			continue
		}
		_ = s.files.CleanupResumablePartial(ctx, job.MountID, item.DestinationPath,
			fmt.Sprintf("%s-%d", job.ID, item.Ordinal))
		item.BytesCompleted, item.UpdatedAt = 0, s.now()
		_ = s.store.UpdateJobItem(ctx, item)
	}
}

func etaConfidence(elapsed float64, completed, total int64) string {
	if elapsed < 3 || total <= 0 || completed*10 < total {
		return "low"
	}
	if elapsed < 10 || completed*2 < total {
		return "medium"
	}
	return "high"
}

func (s *Service) recordEvent(ctx context.Context, job entities.Job, eventType, message string) {
	if eventType == "" {
		return
	}
	_, _ = s.store.RecordJobEvent(ctx, entities.JobEvent{
		JobID: job.ID, Type: eventType, State: job.State, Phase: job.Phase,
		BytesTotal: job.BytesTotal, BytesCompleted: job.BytesCompleted,
		BytesPerSecond: job.BytesPerSecond, ETASeconds: job.ETASeconds,
		ETAConfidence: job.ETAConfidence, Message: message,
		FilesTotal: job.FilesTotal, FilesCompleted: job.FilesCompleted, FilesFailed: job.FilesFailed,
		CorrelationID: job.CorrelationID, CreatedAt: s.now(),
	})
}

func (s *Service) ListEvents(ctx context.Context, after int64, jobID string, limit int) ([]entities.JobEvent, error) {
	return s.store.ListJobEvents(ctx, after, jobID, limit)
}

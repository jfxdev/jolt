package transfers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
)

var (
	ErrInvalid   = errors.New("invalid transfer")
	ErrForbidden = errors.New("transfer is not permitted by the grant")
	ErrPeer      = errors.New("peer is unavailable")
)

type PullRequest struct {
	PeerNodeID         string
	SourceGrantID      string
	SourcePath         string
	DestinationGrantID string
	DestinationPath    string
	ConflictPolicy     string
	VerifyChecksum     bool
	BandwidthLimit     int64
	MaxParallelFiles   int
	MaxParallelChunks  int
	CorrelationID      string
}

type ManifestPage struct {
	SourcePath string               `json:"source_path"`
	Items      []entities.FileEntry `json:"items"`
	NextAfter  int                  `json:"next_after,omitempty"`
	Total      int                  `json:"total"`
}

type SourceFile struct {
	File     *os.File
	Info     os.FileInfo
	ETag     string
	Checksum string
}

func (f SourceFile) CurrentETag() (string, error) {
	info, err := f.File.Stat()
	if err != nil {
		return "", err
	}
	return sourceETag(info), nil
}

type Service struct {
	store             contracts.Store
	files             *filesystem.Service
	jobs              *jobs.Service
	certificates      *joltcrypto.CertificateManager
	chunkSize         int64
	connectTimeout    time.Duration
	idleReadTimeout   time.Duration
	chunkTimeout      time.Duration
	validationTimeout time.Duration
	dialContext       func(context.Context, string, string) (net.Conn, error)
}

func New(store contracts.Store, files *filesystem.Service, jobService *jobs.Service, certificates *joltcrypto.CertificateManager, chunkSize int64) *Service {
	return &Service{
		store: store, files: files, jobs: jobService, certificates: certificates, chunkSize: chunkSize,
		connectTimeout: 10 * time.Second, idleReadTimeout: time.Minute,
		chunkTimeout: 5 * time.Minute, validationTimeout: 2 * time.Minute,
	}
}

func (s *Service) ConfigureTimeouts(connect, idleRead, chunk, validation time.Duration) {
	if connect > 0 {
		s.connectTimeout = connect
	}
	if idleRead > 0 {
		s.idleReadTimeout = idleRead
	}
	if chunk > 0 {
		s.chunkTimeout = chunk
	}
	if validation > 0 {
		s.validationTimeout = validation
	}
}

func (s *Service) ConfigureDialContext(dial func(context.Context, string, string) (net.Conn, error)) {
	s.dialContext = dial
}

func (s *Service) CreatePull(ctx context.Context, request PullRequest, idempotencyKey string) (entities.Job, bool, error) {
	peer, err := s.store.GetPeer(ctx, strings.TrimSpace(request.PeerNodeID))
	if errors.Is(err, db.ErrNotFound) || !trustedPeerState(peer.State) {
		return entities.Job{}, false, fmt.Errorf("%w: exact trusted peer is required", ErrForbidden)
	}
	if err != nil {
		return entities.Job{}, false, err
	}
	if peer.MTLSEndpoint == "" {
		return entities.Job{}, false, fmt.Errorf("%w: peer has no mTLS endpoint", ErrPeer)
	}
	policy := normalizePolicy(request.ConflictPolicy)
	if policy == "ask" {
		return entities.Job{}, false, fmt.Errorf("%w: ask conflicts require an itemized directory transfer", ErrInvalid)
	}
	grant, destination, err := s.receiveDestination(ctx, peer.NodeID, request.DestinationGrantID, request.DestinationPath, request.ConflictPolicy)
	if err != nil {
		return entities.Job{}, false, err
	}
	overwrite := policy == "overwrite" || policy == "checksum"
	if existing, metadataErr := s.files.Metadata(ctx, grant.MountID, destination); metadataErr == nil {
		if existing.Type != "file" {
			return entities.Job{}, false, fmt.Errorf("%w: destination is not a file", ErrInvalid)
		}
		switch policy {
		case "fail":
			return entities.Job{}, false, filesystem.ErrConflict
		case "rename":
			destination, err = s.uniqueDestination(ctx, grant.MountID, destination)
			if err != nil {
				return entities.Job{}, false, err
			}
		case "skip", "overwrite", "checksum":
		}
	} else if !errors.Is(metadataErr, filesystem.ErrNotFound) {
		return entities.Job{}, false, metadataErr
	}
	return s.jobs.Create(ctx, jobs.CreateRequest{
		Type: "transfer_pull", MountID: grant.MountID,
		PeerNodeID: peer.NodeID, SourceGrantID: strings.TrimSpace(request.SourceGrantID),
		DestinationGrantID: grant.ID, SourcePath: cleanRelative(request.SourcePath),
		Destination: destination, ConflictPolicy: policy, Overwrite: overwrite,
		VerifyChecksum:    request.VerifyChecksum || policy == "checksum",
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks,
		CorrelationID:     request.CorrelationID,
	}, idempotencyKey)
}

func (s *Service) OpenSource(ctx context.Context, peerNodeID, grantID, relative string, checksum bool) (SourceFile, error) {
	grant, err := s.store.GetTransferGrant(ctx, grantID)
	if errors.Is(err, db.ErrNotFound) {
		return SourceFile{}, ErrForbidden
	}
	if err != nil {
		return SourceFile{}, err
	}
	if !grant.Enabled || grant.PeerNodeID != peerNodeID ||
		(grant.Direction != "send" && grant.Direction != "send_receive") || !grant.Permissions.Read {
		return SourceFile{}, ErrForbidden
	}
	sourcePath, err := withinGrant(grant.Path, relative)
	if err != nil {
		return SourceFile{}, err
	}
	file, info, err := s.files.Open(ctx, grant.MountID, sourcePath)
	if err != nil {
		return SourceFile{}, err
	}
	result := SourceFile{File: file, Info: info, ETag: sourceETag(info)}
	if checksum {
		result.Checksum, err = s.files.Checksum(ctx, grant.MountID, sourcePath)
		if err != nil {
			file.Close()
			return SourceFile{}, err
		}
	}
	return result, nil
}

func (s *Service) OpenManifest(ctx context.Context, peerNodeID, grantID, relative string, checksum bool, after, limit int) (ManifestPage, error) {
	grant, err := s.sendGrant(ctx, peerNodeID, grantID)
	if err != nil {
		return ManifestPage{}, err
	}
	sourcePath, err := withinGrant(grant.Path, relative)
	if err != nil {
		return ManifestPage{}, err
	}
	root, err := s.files.Metadata(ctx, grant.MountID, sourcePath)
	if err != nil {
		return ManifestPage{}, err
	}
	if root.Type != "directory" {
		return ManifestPage{}, fmt.Errorf("%w: manifest source must be a directory", ErrInvalid)
	}
	if after < 0 {
		after = 0
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	items := make([]entities.FileEntry, 0, limit)
	descendantAfter, descendantLimit := max(after-1, 0), limit
	if after == 0 {
		items = append(items, entities.FileEntry{
			Name: root.Name, Path: ".", Type: "directory", ModifiedAt: root.ModifiedAt,
		})
		descendantLimit--
	}
	var descendants []entities.FileEntry
	descendantTotal := 0
	if descendantLimit > 0 {
		descendants, descendantTotal, err = s.files.ManifestPage(ctx, grant.MountID, sourcePath, descendantAfter, descendantLimit)
		if err != nil {
			return ManifestPage{}, err
		}
	} else {
		_, descendantTotal, err = s.files.ManifestPage(ctx, grant.MountID, sourcePath, 0, 1)
		if err != nil {
			return ManifestPage{}, err
		}
	}
	items = append(items, descendants...)
	if checksum {
		for index := range items {
			if items[index].Type != "file" {
				continue
			}
			items[index].Checksum, err = s.files.Checksum(ctx, grant.MountID, path.Join(sourcePath, items[index].Path))
			if err != nil {
				return ManifestPage{}, err
			}
		}
	}
	total := descendantTotal + 1
	if after > total {
		items = nil
		after = total
	}
	end := after + len(items)
	page := ManifestPage{SourcePath: cleanRelative(relative), Items: items, Total: total}
	if end < total {
		page.NextAfter = end
	}
	return page, nil
}

func (s *Service) PlanDirectoryPull(ctx context.Context, request PullRequest) (entities.CopyPlan, error) {
	peer, err := s.trustedPeer(ctx, request.PeerNodeID)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	grant, destination, err := s.receiveDestination(ctx, peer.NodeID, request.DestinationGrantID, request.DestinationPath, request.ConflictPolicy)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	policy := normalizePolicy(request.ConflictPolicy)
	checksum := request.VerifyChecksum || policy == "checksum"
	entries, err := s.fetchRemoteManifest(ctx, peer, request.SourceGrantID, request.SourcePath, checksum)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	plan := entities.CopyPlan{
		SourcePath: cleanRelative(request.SourcePath), DestinationPath: destination,
		ConflictPolicy: policy, Items: make([]entities.JobItem, 0, len(entries)),
	}
	now := time.Now().UTC()
	blockedDirectories := make(map[string]struct{})
	for index, entry := range entries {
		if entry.Path == ".." || strings.HasPrefix(entry.Path, "../") {
			return entities.CopyPlan{}, fmt.Errorf("%w: remote manifest contains an invalid path", ErrInvalid)
		}
		if entry.Type != "file" && entry.Type != "directory" {
			return entities.CopyPlan{}, fmt.Errorf("%w: remote manifest contains an invalid item type", ErrInvalid)
		}
		if entry.Size < 0 {
			return entities.CopyPlan{}, fmt.Errorf("%w: remote manifest contains an invalid item size", ErrInvalid)
		}
		item := entities.JobItem{
			Ordinal: index, RelativePath: entry.Path, SourcePath: joinRelative(request.SourcePath, entry.Path),
			DestinationPath: joinRelative(destination, entry.Path), Type: entry.Type, Size: entry.Size,
			ModifiedAt: entry.ModifiedAt, Checksum: entry.Checksum, State: "pending", UpdatedAt: now,
		}
		if hasBlockedParent(entry.Path, blockedDirectories) {
			item.Action = "conflict"
		} else {
			item.Action, item.DestinationPath, err = s.planRemoteAction(ctx, grant.MountID, item, policy)
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

func (s *Service) CreateDirectoryPull(ctx context.Context, request PullRequest, idempotencyKey string) (entities.Job, bool, error) {
	plan, err := s.PlanDirectoryPull(ctx, request)
	if err != nil {
		return entities.Job{}, false, err
	}
	grant, err := s.store.GetTransferGrant(ctx, strings.TrimSpace(request.DestinationGrantID))
	if err != nil {
		return entities.Job{}, false, err
	}
	return s.jobs.CreatePlannedDirectoryPull(ctx, jobs.CreateRequest{
		MountID: grant.MountID, PeerNodeID: strings.TrimSpace(request.PeerNodeID),
		SourceGrantID: strings.TrimSpace(request.SourceGrantID), DestinationGrantID: grant.ID,
		SourcePath: cleanRelative(request.SourcePath), Destination: plan.DestinationPath,
		ConflictPolicy: normalizePolicy(request.ConflictPolicy), VerifyChecksum: request.VerifyChecksum,
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks,
		CorrelationID:     request.CorrelationID,
	}, plan, idempotencyKey)
}

func (s *Service) ExecutePull(ctx context.Context, job entities.Job, progress func(int64, int64) error) (int64, error) {
	peer, err := s.trustedPeer(ctx, job.PeerNodeID)
	if err != nil {
		return job.BytesCompleted, err
	}
	if peer.State == "offline" || peer.State == "degraded" {
		return job.BytesCompleted, fmt.Errorf("%w: peer is %s", jobs.ErrWaitingPeer, peer.State)
	}
	grant, err := s.receiveGrant(ctx, peer.NodeID, job.DestinationGrantID, job.ConflictPolicy)
	if err != nil {
		return job.BytesCompleted, err
	}
	return s.executePullFile(ctx, peer, grant, job, progress)
}

func (s *Service) executePullFile(ctx context.Context, peer entities.Peer, grant entities.TransferPathGrant, job entities.Job, progress func(int64, int64) error) (int64, error) {
	if job.ConflictPolicy == "skip" {
		if _, err := s.files.Metadata(ctx, grant.MountID, job.Destination); err == nil {
			return 0, nil
		}
	}
	checkpoint := job.BytesCompleted
	if checkpoint > 0 && job.SourceETag == "" {
		checkpoint = 0
		_ = s.files.CleanupResumablePartial(ctx, grant.MountID, job.Destination, job.ID)
	}
	expectedChecksum := ""
	metadataTotal := int64(-1)
	metadataETag := ""
	if job.VerifyChecksum || job.MaxParallelChunks > 1 {
		metadataResponse, metadataErr := s.openRemote(ctx, peer, job, 0, -1, http.MethodHead, job.VerifyChecksum)
		if metadataErr != nil {
			return checkpoint, metadataErr
		}
		metadataResponse.Body.Close()
		if metadataResponse.StatusCode == http.StatusPreconditionFailed {
			return checkpoint, filesystem.ErrSourceChanged
		}
		if metadataResponse.StatusCode != http.StatusOK {
			return checkpoint, fmt.Errorf("remote metadata returned HTTP %d", metadataResponse.StatusCode)
		}
		etag := metadataResponse.Header.Get("ETag")
		metadataETag = etag
		expectedChecksum = metadataResponse.Header.Get("X-Jolt-SHA256")
		var sizeErr error
		metadataTotal, sizeErr = strconv.ParseInt(metadataResponse.Header.Get("X-Jolt-File-Size"), 10, 64)
		if sizeErr != nil || metadataTotal < 0 || checkpoint > metadataTotal || etag == "" ||
			(job.VerifyChecksum && expectedChecksum == "") ||
			(job.SourceETag != "" && etag != job.SourceETag) {
			return checkpoint, filesystem.ErrSourceChanged
		}
		if job.SourceETag == "" {
			job.SourceETag = etag
			if err := s.store.UpdateJob(ctx, job); err != nil {
				return checkpoint, err
			}
		}
		if job.ConflictPolicy == "checksum" {
			if _, metadataErr := s.files.Metadata(ctx, grant.MountID, job.Destination); metadataErr == nil {
				localChecksum, checksumErr := s.files.Checksum(ctx, grant.MountID, job.Destination)
				if checksumErr != nil {
					return checkpoint, checksumErr
				}
				if localChecksum == expectedChecksum {
					return 0, nil
				}
			}
		}
	}
	if job.MaxParallelChunks > 1 {
		etag := metadataETag
		total := metadataTotal
		written, _, receiveErr := s.files.ReceiveFileResumableRanges(ctx, grant.MountID, job.Destination,
			job.ID, job.Overwrite, checkpoint, s.chunkSize, total, job.MaxParallelChunks, expectedChecksum,
			func(rangeContext context.Context, start, end int64) (io.ReadCloser, func() error, error) {
				currentPeer, validationErr := s.trustedPeer(rangeContext, job.PeerNodeID)
				if validationErr != nil {
					return nil, nil, validationErr
				}
				if _, validationErr = s.receiveGrant(rangeContext, currentPeer.NodeID,
					job.DestinationGrantID, job.ConflictPolicy); validationErr != nil {
					return nil, nil, validationErr
				}
				rangeJob := job
				rangeJob.SourceETag = etag
				response, requestErr := s.openRemote(rangeContext, currentPeer, rangeJob, start, end, http.MethodGet, false)
				if requestErr != nil {
					return nil, nil, requestErr
				}
				fail := func(err error) (io.ReadCloser, func() error, error) {
					response.Body.Close()
					return nil, nil, err
				}
				if response.StatusCode == http.StatusPreconditionFailed {
					return fail(filesystem.ErrSourceChanged)
				}
				if response.StatusCode != http.StatusPartialContent {
					return fail(fmt.Errorf("remote range returned HTTP %d", response.StatusCode))
				}
				responseTotal, sizeErr := strconv.ParseInt(response.Header.Get("X-Jolt-File-Size"), 10, 64)
				expectedContentRange := fmt.Sprintf("bytes %d-%d/%d", start, end, total)
				if sizeErr != nil || responseTotal != total || response.Header.Get("ETag") != etag ||
					response.Header.Get("Content-Range") != expectedContentRange {
					return fail(filesystem.ErrSourceChanged)
				}
				return response.Body, func() error {
					if finalETag := response.Trailer.Get("X-Jolt-Final-ETag"); finalETag == "" || finalETag != etag {
						return filesystem.ErrSourceChanged
					}
					return nil
				}, nil
			}, progress, s.jobs.BandwidthLimiter(job))
		return written, receiveErr
	}
	response, err := s.openRemote(ctx, peer, job, checkpoint, -1, http.MethodGet, false)
	if err != nil {
		return checkpoint, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusPreconditionFailed {
		return checkpoint, filesystem.ErrSourceChanged
	}
	expectedStatus := http.StatusOK
	if checkpoint > 0 {
		expectedStatus = http.StatusPartialContent
	}
	if response.StatusCode != expectedStatus {
		return checkpoint, fmt.Errorf("remote transfer returned HTTP %d", response.StatusCode)
	}
	total, err := strconv.ParseInt(response.Header.Get("X-Jolt-File-Size"), 10, 64)
	if err != nil || total < 0 || checkpoint > total {
		return checkpoint, fmt.Errorf("%w: remote file size is invalid", ErrInvalid)
	}
	etag := response.Header.Get("ETag")
	if etag == "" || (job.SourceETag != "" && etag != job.SourceETag) {
		return checkpoint, filesystem.ErrSourceChanged
	}
	if job.SourceETag == "" {
		job.SourceETag = etag
		if err := s.store.UpdateJob(ctx, job); err != nil {
			return checkpoint, err
		}
	}
	written, _, err := s.files.ReceiveFileResumable(ctx, grant.MountID, job.Destination, job.ID,
		job.Overwrite, checkpoint, s.chunkSize, total, expectedChecksum, response.Body, progress, func() error {
			if finalETag := response.Trailer.Get("X-Jolt-Final-ETag"); finalETag == "" || finalETag != etag {
				return filesystem.ErrSourceChanged
			}
			return nil
		}, s.jobs.BandwidthLimiter(job))
	return written, err
}

func (s *Service) ExecuteDirectoryPull(ctx context.Context, job entities.Job, progress func(int64, int64, int, int) error) (int64, error) {
	peer, err := s.trustedPeer(ctx, job.PeerNodeID)
	if err != nil {
		return job.BytesCompleted, err
	}
	if peer.State == "offline" || peer.State == "degraded" {
		return job.BytesCompleted, fmt.Errorf("%w: peer is %s", jobs.ErrWaitingPeer, peer.State)
	}
	grant, err := s.receiveGrant(ctx, peer.NodeID, job.DestinationGrantID, job.ConflictPolicy)
	if err != nil {
		return job.BytesCompleted, err
	}
	items, err := s.store.ListJobItems(ctx, job.ID)
	if err != nil {
		return job.BytesCompleted, err
	}
	var stateMu sync.Mutex
	var bytesCompleted int64
	var filesCompleted, filesFailed, warnings int
	for _, item := range items {
		if item.Type == "file" {
			bytesCompleted += item.BytesCompleted
			if item.State == "completed" || item.State == "skipped" {
				filesCompleted++
			}
		}
	}
	var pendingFiles []entities.JobItem
	for _, item := range items {
		if item.State == "completed" || item.State == "skipped" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return bytesCompleted, err
		}
		item.Attempt++
		item.Error, item.UpdatedAt = "", time.Now().UTC()
		switch item.Action {
		case "skip":
			item.State = "skipped"
			if item.Type == "file" {
				filesCompleted++
			}
		case "conflict":
			if job.ConflictPolicy == "ask" {
				item.State, item.Error = "waiting_user_decision", "destination conflict requires a decision"
				_ = s.store.UpdateJobItem(ctx, item)
				return bytesCompleted, jobs.ErrWaitingUserDecision
			}
			item.State, item.Error = "failed", "destination conflict"
			warnings++
			if item.Type == "file" {
				filesFailed++
			}
		case "fail":
			item.State, item.Error = "failed", "destination conflict rejected by user"
			warnings++
			if item.Type == "file" {
				filesFailed++
			}
		case "merge":
			item.State = "completed"
		case "create":
			if err := s.files.CreateDirectory(ctx, grant.MountID, item.DestinationPath); err != nil {
				item.State, item.Error = "failed", err.Error()
				_ = s.store.UpdateJobItem(context.Background(), item)
				return bytesCompleted, err
			}
			item.State = "completed"
		case "copy", "overwrite", "rename":
			pendingFiles = append(pendingFiles, item)
			continue
		default:
			return bytesCompleted, fmt.Errorf("%w: unsupported remote plan action %q", ErrInvalid, item.Action)
		}
		if err := s.store.UpdateJobItem(ctx, item); err != nil {
			return bytesCompleted, err
		}
		if err := progress(bytesCompleted, job.BytesTotal, filesCompleted, filesFailed); err != nil {
			return bytesCompleted, err
		}
	}
	parallelism := job.MaxParallelFiles
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > len(pendingFiles) {
		parallelism = len(pendingFiles)
	}
	if parallelism > 0 {
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
					item.State = "running"
					if err := s.store.UpdateJobItem(workContext, item); err != nil {
						results <- err
						continue
					}
					fileJob := job
					fileJob.ParentJobID = job.ID
					fileJob.ID = fmt.Sprintf("%s-%d", job.ID, item.Ordinal)
					fileJob.SourcePath, fileJob.Destination = item.SourcePath, item.DestinationPath
					fileJob.SourceETag = sourceEntryETag(item)
					fileJob.BytesCompleted, fileJob.Overwrite = item.BytesCompleted, item.Action == "overwrite"
					fileJob.VerifyChecksum = job.VerifyChecksum || job.ConflictPolicy == "checksum"
					written, pullErr := s.executePullFile(workContext, peer, grant, fileJob, func(completed, _ int64) error {
						stateMu.Lock()
						bytesCompleted += completed - item.BytesCompleted
						item.BytesCompleted, item.UpdatedAt = completed, time.Now().UTC()
						currentBytes, currentCompleted, currentFailed := bytesCompleted, filesCompleted, filesFailed
						stateMu.Unlock()
						if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
							return err
						}
						return progress(currentBytes, job.BytesTotal, currentCompleted, currentFailed)
					})
					if pullErr != nil {
						item.UpdatedAt = time.Now().UTC()
						if errors.Is(pullErr, context.Canceled) {
							item.State, item.Error = "pending", ""
						} else {
							item.State, item.Error = "failed", pullErr.Error()
							stateMu.Lock()
							filesFailed++
							stateMu.Unlock()
						}
						_ = s.store.UpdateJobItem(context.Background(), item)
						results <- pullErr
						continue
					}
					stateMu.Lock()
					bytesCompleted += written - item.BytesCompleted
					item.State, item.BytesCompleted, item.UpdatedAt = "completed", written, time.Now().UTC()
					filesCompleted++
					currentBytes, currentCompleted, currentFailed := bytesCompleted, filesCompleted, filesFailed
					stateMu.Unlock()
					if err := s.store.UpdateJobItem(context.Background(), item); err != nil {
						results <- err
						continue
					}
					results <- progress(currentBytes, job.BytesTotal, currentCompleted, currentFailed)
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
		if firstErr != nil {
			stateMu.Lock()
			completed := bytesCompleted
			stateMu.Unlock()
			return completed, firstErr
		}
	}
	if warnings > 0 {
		return bytesCompleted, fmt.Errorf("%w: %d remote item(s) could not be copied", jobs.ErrWarnings, warnings)
	}
	return bytesCompleted, nil
}

func (s *Service) CleanupPull(ctx context.Context, job entities.Job) error {
	return s.files.CleanupResumablePartial(ctx, job.MountID, job.Destination, job.ID)
}

func (s *Service) CleanupDirectoryPull(ctx context.Context, job entities.Job) error {
	items, err := s.store.ListJobItems(ctx, job.ID)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Type != "file" || item.State == "completed" || item.State == "skipped" {
			continue
		}
		if err := s.files.CleanupResumablePartial(ctx, job.MountID, item.DestinationPath,
			fmt.Sprintf("%s-%d", job.ID, item.Ordinal)); err != nil {
			return err
		}
		item.BytesCompleted, item.UpdatedAt = 0, time.Now().UTC()
		if err := s.store.UpdateJobItem(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) openRemote(ctx context.Context, peer entities.Peer, job entities.Job, rangeStart, rangeEnd int64, method string, includeChecksum bool) (*http.Response, error) {
	endpoint, err := url.Parse(strings.TrimRight(peer.MTLSEndpoint, "/"))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return nil, fmt.Errorf("%w: invalid peer mTLS endpoint", ErrPeer)
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/peer/v1/grants/" + url.PathEscape(job.SourceGrantID) + "/content"
	query := endpoint.Query()
	query.Set("path", job.SourcePath)
	if includeChecksum {
		query.Set("checksum", "true")
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet && (rangeStart > 0 || rangeEnd >= 0) {
		if rangeEnd >= 0 {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd))
		} else {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", rangeStart))
		}
	}
	if job.SourceETag != "" {
		request.Header.Set("If-Match", job.SourceETag)
	}
	transport := s.peerTransport(peer)
	client := &http.Client{Transport: transport}
	response, err := client.Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: %v", jobs.ErrWaitingPeer, err)
	}
	response.Body = &closingBody{ReadCloser: response.Body, close: transport.CloseIdleConnections}
	return response, nil
}

func (s *Service) peerTransport(peer entities.Peer) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig:    s.certificates.ClientTLSConfig(peer.NodeID, peer.Fingerprint, peer.PreviousFingerprint),
		DisableCompression: true, TLSHandshakeTimeout: s.connectTimeout,
		ResponseHeaderTimeout: s.validationTimeout, IdleConnTimeout: s.idleReadTimeout,
	}
	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: s.connectTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	readTimeout := s.idleReadTimeout
	if s.chunkTimeout < readTimeout {
		readTimeout = s.chunkTimeout
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &readDeadlineConn{Conn: connection, timeout: readTimeout}, nil
	}
	return transport
}

func (s *Service) fetchRemoteManifest(ctx context.Context, peer entities.Peer, grantID, sourcePath string, checksum bool) ([]entities.FileEntry, error) {
	items := make([]entities.FileEntry, 0)
	after := 0
	for {
		endpoint, err := url.Parse(strings.TrimRight(peer.MTLSEndpoint, "/"))
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
			return nil, fmt.Errorf("%w: invalid peer mTLS endpoint", ErrPeer)
		}
		endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/peer/v1/grants/" + url.PathEscape(grantID) + "/manifest"
		query := endpoint.Query()
		query.Set("path", cleanRelative(sourcePath))
		query.Set("after", strconv.Itoa(after))
		query.Set("limit", "500")
		if checksum {
			query.Set("checksum", "true")
		}
		endpoint.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}
		response, err := s.doPeerRequest(peer, request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			if response.StatusCode == http.StatusForbidden {
				return nil, ErrForbidden
			}
			if response.StatusCode == http.StatusNotFound {
				return nil, filesystem.ErrNotFound
			}
			return nil, fmt.Errorf("remote manifest returned HTTP %d", response.StatusCode)
		}
		var page ManifestPage
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&page)
		response.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}
		items = append(items, page.Items...)
		if page.NextAfter == 0 {
			return items, nil
		}
		if page.NextAfter <= after || page.NextAfter > page.Total {
			return nil, fmt.Errorf("%w: remote manifest cursor is invalid", ErrInvalid)
		}
		after = page.NextAfter
	}
}

func (s *Service) doPeerRequest(peer entities.Peer, request *http.Request) (*http.Response, error) {
	transport := s.peerTransport(peer)
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, fmt.Errorf("%w: %v", jobs.ErrWaitingPeer, err)
	}
	response.Body = &closingBody{ReadCloser: response.Body, close: transport.CloseIdleConnections}
	return response, nil
}

type readDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *readDeadlineConn) Read(buffer []byte) (int, error) {
	if c.timeout > 0 {
		if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(buffer)
}

func (s *Service) planRemoteAction(ctx context.Context, mountID string, item entities.JobItem, policy string) (string, string, error) {
	existing, err := s.files.Metadata(ctx, mountID, item.DestinationPath)
	if err != nil && !errors.Is(err, filesystem.ErrNotFound) {
		return "", item.DestinationPath, err
	}
	if errors.Is(err, filesystem.ErrNotFound) {
		if item.Type == "directory" {
			return "create", item.DestinationPath, nil
		}
		return "copy", item.DestinationPath, nil
	}
	if item.Type == "directory" {
		if existing.Type == "directory" {
			return "merge", item.DestinationPath, nil
		}
		return "conflict", item.DestinationPath, nil
	}
	if existing.Type != "file" {
		return "conflict", item.DestinationPath, nil
	}
	switch policy {
	case "skip":
		return "skip", item.DestinationPath, nil
	case "overwrite":
		return "overwrite", item.DestinationPath, nil
	case "rename":
		destination, err := s.uniqueDestination(ctx, mountID, item.DestinationPath)
		return "rename", destination, err
	case "checksum":
		if item.Checksum == "" {
			return "", item.DestinationPath, fmt.Errorf("%w: checksum policy requires remote checksums", ErrInvalid)
		}
		localChecksum, err := s.files.Checksum(ctx, mountID, item.DestinationPath)
		if err != nil {
			return "", item.DestinationPath, err
		}
		if localChecksum == item.Checksum {
			return "skip", item.DestinationPath, nil
		}
		return "overwrite", item.DestinationPath, nil
	default:
		return "conflict", item.DestinationPath, nil
	}
}

func (s *Service) trustedPeer(ctx context.Context, nodeID string) (entities.Peer, error) {
	peer, err := s.store.GetPeer(ctx, strings.TrimSpace(nodeID))
	if errors.Is(err, db.ErrNotFound) || (err == nil && !trustedPeerState(peer.State)) {
		return entities.Peer{}, fmt.Errorf("%w: exact trusted peer is required", ErrForbidden)
	}
	if err != nil {
		return entities.Peer{}, err
	}
	if peer.MTLSEndpoint == "" {
		return entities.Peer{}, fmt.Errorf("%w: peer has no mTLS endpoint", ErrPeer)
	}
	return peer, nil
}

func (s *Service) sendGrant(ctx context.Context, peerNodeID, grantID string) (entities.TransferPathGrant, error) {
	grant, err := s.store.GetTransferGrant(ctx, strings.TrimSpace(grantID))
	if errors.Is(err, db.ErrNotFound) {
		return grant, ErrForbidden
	}
	if err != nil {
		return grant, err
	}
	if !grant.Enabled || grant.PeerNodeID != peerNodeID ||
		(grant.Direction != "send" && grant.Direction != "send_receive") || !grant.Permissions.Read {
		return grant, ErrForbidden
	}
	return grant, nil
}

func (s *Service) receiveGrant(ctx context.Context, peerNodeID, grantID, policy string) (entities.TransferPathGrant, error) {
	grant, err := s.store.GetTransferGrant(ctx, strings.TrimSpace(grantID))
	if errors.Is(err, db.ErrNotFound) {
		return grant, ErrForbidden
	}
	if err != nil {
		return grant, err
	}
	if !grant.Enabled || grant.PeerNodeID != peerNodeID ||
		(grant.Direction != "receive" && grant.Direction != "send_receive") || !grant.Permissions.Write {
		return grant, ErrForbidden
	}
	if policy = normalizePolicy(policy); !contains(grant.ConflictPolicies, policy) {
		return grant, fmt.Errorf("%w: conflict policy is not allowed by the destination grant", ErrForbidden)
	}
	return grant, nil
}

func (s *Service) receiveDestination(ctx context.Context, peerNodeID, grantID, relative, policy string) (entities.TransferPathGrant, string, error) {
	grant, err := s.receiveGrant(ctx, peerNodeID, grantID, policy)
	if err != nil {
		return grant, "", err
	}
	destination, err := withinGrant(grant.Path, relative)
	return grant, destination, err
}

func hasBlockedParent(relative string, blocked map[string]struct{}) bool {
	for current := path.Dir(relative); current != "." && current != "/"; current = path.Dir(current) {
		if _, exists := blocked[current]; exists {
			return true
		}
	}
	_, blockedRoot := blocked["."]
	return blockedRoot
}

func joinRelative(base, relative string) string {
	if relative == "" || relative == "." {
		return cleanRelative(base)
	}
	if base == "" || base == "." {
		return cleanRelative(relative)
	}
	return cleanRelative(path.Join(base, relative))
}

func sourceEntryETag(item entities.JobItem) string {
	return fmt.Sprintf(`"%x-%x"`, item.Size, item.ModifiedAt.UTC().UnixNano())
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
	return "", fmt.Errorf("%w: no conflict-free destination name is available", ErrInvalid)
}

func withinGrant(base, relative string) (string, error) {
	relative = cleanRelative(relative)
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return "", filesystem.ErrTraversal
	}
	base = cleanRelative(base)
	joined := path.Join(base, relative)
	if base != "." && joined != base && !strings.HasPrefix(joined, base+"/") {
		return "", filesystem.ErrTraversal
	}
	return cleanRelative(joined), nil
}

func cleanRelative(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	value = strings.TrimLeft(value, "/")
	cleaned := path.Clean(value)
	if cleaned == "" || cleaned == "/" {
		return "."
	}
	return cleaned
}

func normalizePolicy(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "fail"
	}
	return value
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func trustedPeerState(state string) bool {
	switch state {
	case "trusted", "unknown", "online", "offline", "degraded":
		return true
	default:
		return false
	}
}

func sourceETag(info os.FileInfo) string {
	return fmt.Sprintf(`"%x-%x"`, info.Size(), info.ModTime().UTC().UnixNano())
}

type closingBody struct {
	io.ReadCloser
	close func()
}

func (b *closingBody) Close() error {
	err := b.ReadCloser.Close()
	b.close()
	return err
}

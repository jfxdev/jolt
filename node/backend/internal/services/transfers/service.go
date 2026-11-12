package transfers

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filepolicy"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"

	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

var (
	ErrInvalid             = errors.New("invalid transfer")
	ErrForbidden           = errors.New("transfer is not permitted by the grant")
	ErrPeer                = errors.New("peer is unavailable")
	ErrPeerUpgradeRequired = errors.New("peer must be upgraded to support protected move validation")
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

// BatchPullRequest is intentionally grant-relative: it is the node-internal
// contract used after the Control Tower has resolved logical node/mount/path
// references to exact grants.
type BatchPullRequest struct {
	PullRequest
	// SubjectType, MovePlanID and MovePlanToken belong to a signed move: the
	// Control Tower names the authenticated subject, and the move consumes the
	// one-use confirmation of its plan.
	SubjectType   string
	MovePlanID    string
	MovePlanToken string
	SourcePaths   []string
	// SourceNames preserve mount-relative root names when a selected path is
	// exactly the root of a more restrictive send grant.
	SourceNames []string
	Operation   string
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

type serviceStore interface {
	contracts.ConfigurationReader
	contracts.TrustStore
	contracts.JobStore
}

type Service struct {
	store             serviceStore
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

func New(store serviceStore, files *filesystem.Service, jobService *jobs.Service, certificates *joltcrypto.CertificateManager, chunkSize int64) *Service {
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
	if errors.Is(err, contracts.ErrNotFound) || !entities.TrustedPeerState(peer.State) {
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
			destination, err = s.uniqueDestination(ctx, grant, destination)
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
	grant, err := s.sendGrant(ctx, peerNodeID, grantID)
	if err != nil {
		return SourceFile{}, err
	}
	sourcePath, err := withinGrantWithExclusions(grant, relative)
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
	sourcePath, err := withinGrantWithExclusions(grant, relative)
	if err != nil {
		return ManifestPage{}, err
	}
	root, err := s.files.Metadata(ctx, grant.MountID, sourcePath)
	if err != nil {
		return ManifestPage{}, err
	}
	if root.Type == "file" {
		entry := entities.FileEntry{Name: root.Name, Path: ".", Type: "file", Size: root.Size, ModifiedAt: root.ModifiedAt}
		if checksum {
			entry.Checksum, err = s.files.Checksum(ctx, grant.MountID, sourcePath)
			if err != nil {
				return ManifestPage{}, err
			}
		}
		return ManifestPage{SourcePath: cleanRelative(relative), Items: []entities.FileEntry{entry}, Total: 1}, nil
	}
	if root.Type != "directory" {
		return ManifestPage{}, fmt.Errorf("%w: manifest source type is unsupported", ErrInvalid)
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
		descendants, descendantTotal, err = s.files.ManifestPageWithExclusions(ctx, grant.MountID, sourcePath, descendantAfter, descendantLimit, grant.Exclude)
		if err != nil {
			return ManifestPage{}, err
		}
	} else {
		_, descendantTotal, err = s.files.ManifestPageWithExclusions(ctx, grant.MountID, sourcePath, 0, 1, grant.Exclude)
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
	for _, entry := range entries {
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
			Ordinal: len(plan.Items), RelativePath: entry.Path, SourcePath: joinRelative(request.SourcePath, entry.Path),
			DestinationPath: joinRelative(destination, entry.Path), Type: entry.Type, Size: entry.Size,
			ModifiedAt: entry.ModifiedAt, Checksum: entry.Checksum, State: "pending", UpdatedAt: now,
		}
		if err := validateGrantDestination(grant, item.DestinationPath); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return entities.CopyPlan{}, err
		}
		if hasBlockedParent(entry.Path, blockedDirectories) {
			item.Action = "conflict"
		} else {
			item.Action, item.DestinationPath, err = s.planRemoteAction(ctx, grant, item, policy)
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

func (s *Service) PlanBatchPull(ctx context.Context, request BatchPullRequest) (entities.CopyPlan, error) {
	plan, _, err := s.planBatch(ctx, request, nil)
	return plan, err
}

// planBatch plans a batch pull. With access, only source entries the signed
// policy lets the actor list and read are planned and every destination is
// checked against it; omitted counts the source entries left out.
func (s *Service) planBatch(ctx context.Context, request BatchPullRequest, access *jobs.TransferAccess) (entities.CopyPlan, int, error) {
	operation := strings.ToLower(strings.TrimSpace(request.Operation))
	if operation == "" {
		operation = "copy"
	}
	if operation != "copy" && operation != "move" {
		return entities.CopyPlan{}, 0, fmt.Errorf("%w: operation must be copy or move", ErrInvalid)
	}
	paths, err := normalizeBatchPaths(request.SourcePaths)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	sourceNames, err := batchSourceNames(request.SourcePaths, request.SourceNames)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	peer, err := s.trustedPeer(ctx, request.PeerNodeID)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	destinationGrant, destinationBase, err := s.receiveDestination(ctx, peer.NodeID, request.DestinationGrantID, request.DestinationPath, request.ConflictPolicy)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	policy := normalizePolicy(request.ConflictPolicy)
	checksum := request.VerifyChecksum || policy == "checksum" || operation == "move"
	plan := entities.CopyPlan{
		DestinationPath: destinationBase, ConflictPolicy: policy,
		Items: make([]entities.JobItem, 0),
	}
	omitted := 0
	seenDestinations := make(map[string]struct{}, len(paths))
	for _, sourcePath := range paths {
		if operation == "move" {
			if err := s.validateRemoteMoveSource(ctx, peer, request.SourceGrantID, sourcePath); err != nil {
				return entities.CopyPlan{}, 0, err
			}
		}
		rootName := sourceNames[sourcePath]
		if rootName == "" {
			rootName = path.Base(sourcePath)
		}
		if _, exists := seenDestinations[rootName]; exists {
			return entities.CopyPlan{}, 0, fmt.Errorf("%w: selected roots map to the same destination name", ErrInvalid)
		}
		seenDestinations[rootName] = struct{}{}
		rootDestination := joinRelative(destinationBase, rootName)
		rootPlan, rootOmitted, err := s.planBatchRoot(ctx, peer, request.SourceGrantID, sourcePath, destinationGrant, rootDestination, policy, checksum, operation, access)
		if err != nil {
			return entities.CopyPlan{}, 0, err
		}
		for index := range rootPlan.Items {
			item := &rootPlan.Items[index]
			item.Ordinal = len(plan.Items)
			// relative_path is the durable primary key for job items. Source paths
			// are unique after overlap validation, including items from many roots.
			item.RelativePath = item.SourcePath
			if item.SourcePath == sourcePath {
				item.SourceRoot = true
			}
			if operation == "move" {
				// Every manifest entry carries its own checkpoint and ETag. Cleanup
				// can therefore delete files first and only empty directories after
				// a restart, without recursively removing a changed source tree.
				item.SourceCleanupState = "pending"
			}
			plan.Items = append(plan.Items, *item)
		}
		omitted += rootOmitted
		plan.BytesTotal += rootPlan.BytesTotal
		plan.FilesTotal += rootPlan.FilesTotal
		plan.CopyCount += rootPlan.CopyCount
		plan.SkipCount += rootPlan.SkipCount
		plan.RenameCount += rootPlan.RenameCount
		plan.ConflictCount += rootPlan.ConflictCount
	}
	return plan, omitted, nil
}

func (s *Service) CreateBatchPull(ctx context.Context, request BatchPullRequest, idempotencyKey, requestHash string) (entities.Job, bool, error) {
	if job, storedHash, found, err := s.store.FindJobByIdempotency(ctx, idempotencyKey); err != nil {
		return entities.Job{}, false, err
	} else if found {
		if storedHash != requestHash {
			return entities.Job{}, false, contracts.ErrIdempotencyConflict
		}
		return job, true, nil
	}
	plan, err := s.PlanBatchPull(ctx, request)
	if err != nil {
		return entities.Job{}, false, err
	}
	operation := strings.ToLower(strings.TrimSpace(request.Operation))
	if operation == "" {
		operation = "copy"
	}
	typeName := "transfer_pull_batch"
	if operation == "move" {
		typeName = "transfer_move_batch"
	}
	destinationGrant, err := s.store.GetTransferGrant(ctx, strings.TrimSpace(request.DestinationGrantID))
	if err != nil {
		return entities.Job{}, false, err
	}
	return s.jobs.CreatePlannedBatchPull(ctx, jobs.CreateRequest{
		Type: typeName, MountID: destinationGrant.MountID, PeerNodeID: strings.TrimSpace(request.PeerNodeID),
		SourceGrantID: strings.TrimSpace(request.SourceGrantID), DestinationGrantID: strings.TrimSpace(request.DestinationGrantID),
		Destination: plan.DestinationPath, ConflictPolicy: normalizePolicy(request.ConflictPolicy),
		VerifyChecksum: request.VerifyChecksum || operation == "move",
		BandwidthLimit: request.BandwidthLimit, MaxParallelFiles: request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks, CorrelationID: request.CorrelationID,
	}, plan, idempotencyKey, requestHash)
}

func (s *Service) planBatchRoot(ctx context.Context, peer entities.Peer, sourceGrantID, sourcePath string, grant entities.TransferPathGrant, destinationPath, policy string, checksum bool, operation string, access *jobs.TransferAccess) (entities.CopyPlan, int, error) {
	entries, err := s.fetchRemoteManifest(ctx, peer, sourceGrantID, sourcePath, checksum)
	if err != nil {
		return entities.CopyPlan{}, 0, err
	}
	plan := entities.CopyPlan{SourcePath: sourcePath, DestinationPath: destinationPath, ConflictPolicy: policy, Items: make([]entities.JobItem, 0, len(entries))}
	now := time.Now().UTC()
	blockedDirectories := make(map[string]struct{})
	omittedDirectories := make(map[string]struct{})
	omitted := 0
	for _, entry := range entries {
		if entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || (entry.Type != "file" && entry.Type != "directory") || entry.Size < 0 {
			return entities.CopyPlan{}, 0, fmt.Errorf("%w: remote manifest contains an invalid item", ErrInvalid)
		}
		if access != nil {
			// Descendants of an omitted directory are never judged, so their names
			// are not even evaluated.
			if hasBlockedParent(entry.Path, omittedDirectories) {
				continue // counted once, with the directory that hides it
			}
			mountPath := access.SourceMountPath(joinRelative(sourcePath, entry.Path))
			if !access.Source.AllowsListedEntry(mountPath, entry.Type) {
				if entry.Path == "." {
					return entities.CopyPlan{}, 0, filesystem.ErrFilteredHidden
				}
				omitted++
				if entry.Type == "directory" {
					omittedDirectories[entry.Path] = struct{}{}
				}
				continue
			}
		}
		item := entities.JobItem{
			SourcePath: joinRelative(sourcePath, entry.Path), DestinationPath: joinRelative(destinationPath, entry.Path),
			Type: entry.Type, Size: entry.Size, ModifiedAt: entry.ModifiedAt, Checksum: entry.Checksum,
			State: "pending", UpdatedAt: now,
		}
		if err := validateGrantDestination(grant, item.DestinationPath); err != nil {
			if errors.Is(err, ErrForbidden) && operation == "copy" {
				continue
			}
			return entities.CopyPlan{}, 0, err
		}
		if hasBlockedParent(entry.Path, blockedDirectories) {
			item.Action = "conflict"
		} else {
			item.Action, item.DestinationPath, err = s.planRemoteAction(ctx, grant, item, policy)
			if err != nil {
				return entities.CopyPlan{}, 0, err
			}
			if access != nil {
				if err := s.checkDestinationAccess(ctx, grant.MountID, item, access); err != nil {
					return entities.CopyPlan{}, 0, err
				}
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
	return plan, omitted, nil
}

func normalizeBatchPaths(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: at least one source path is required", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(values))
	paths := make([]string, 0, len(values))
	for _, value := range values {
		cleaned := cleanRelative(value)
		if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return nil, fmt.Errorf("%w: source path is invalid", ErrInvalid)
		}
		if _, exists := seen[cleaned]; exists {
			return nil, fmt.Errorf("%w: source paths must be unique", ErrInvalid)
		}
		seen[cleaned] = struct{}{}
		paths = append(paths, cleaned)
	}
	sort.Strings(paths)
	if len(paths) > 1 && paths[0] == "." {
		return nil, fmt.Errorf("%w: selected paths cannot overlap", ErrInvalid)
	}
	for index := 1; index < len(paths); index++ {
		if strings.HasPrefix(paths[index], paths[index-1]+"/") {
			return nil, fmt.Errorf("%w: selected paths cannot overlap", ErrInvalid)
		}
	}
	return paths, nil
}

func batchSourceNames(paths, supplied []string) (map[string]string, error) {
	if len(supplied) != 0 && len(supplied) != len(paths) {
		return nil, fmt.Errorf("%w: source names must match source paths", ErrInvalid)
	}
	names := make(map[string]string, len(paths))
	for index, sourcePath := range paths {
		cleaned := cleanRelative(sourcePath)
		name := ""
		if len(supplied) > 0 {
			name = cleanRelative(supplied[index])
			if name == "." || name == ".." || strings.Contains(name, "/") {
				return nil, fmt.Errorf("%w: source name is invalid", ErrInvalid)
			}
		}
		if cleaned == "." && name == "" {
			return nil, fmt.Errorf("%w: a selected grant root requires a source name", ErrInvalid)
		}
		if name != "" {
			names[cleaned] = name
		}
	}
	return names, nil
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
	if grant.MountID != job.MountID {
		return job.BytesCompleted, ErrForbidden
	}
	if err := validateGrantDestination(grant, job.Destination); err != nil {
		return job.BytesCompleted, err
	}
	validatePublication := func() error {
		currentPeer, err := s.trustedPeer(ctx, job.PeerNodeID)
		if err != nil {
			return err
		}
		currentGrant, err := s.receiveGrant(ctx, currentPeer.NodeID, job.DestinationGrantID, job.ConflictPolicy)
		if err != nil {
			return err
		}
		if currentGrant.MountID != job.MountID {
			return ErrForbidden
		}
		if err := validateGrantDestination(currentGrant, job.Destination); err != nil {
			return err
		}
		if access, filtered := jobs.TransferAccessFrom(ctx); filtered {
			// The signed policy is checked again right before the file appears.
			_, _, err := s.files.InspectCopyDestinationFiltered(ctx, currentGrant.MountID, job.Destination, "file", access.Destination)
			return err
		}
		return nil
	}
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
			}, progress, validatePublication, s.jobs.BandwidthLimiter(job))
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
			return validatePublication()
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
	// A job bound to a signed authorization never runs without its filters.
	access, filtered := jobs.TransferAccessFrom(ctx)
	if (job.SignedAuthBound || job.RequiresSignedAuth) && !filtered {
		return job.BytesCompleted, ErrForbidden
	}
	items, err := s.store.ListJobItems(ctx, job.ID)
	if err != nil {
		return job.BytesCompleted, err
	}
	if grant.MountID != job.MountID {
		return job.BytesCompleted, ErrForbidden
	}
	if err := validateGrantDestination(grant, job.Destination); err != nil {
		return job.BytesCompleted, err
	}
	// Validate every persisted item before changing anything, including completed
	// entries that may later trigger source cleanup on resumed moves.
	for _, item := range items {
		if err := validateGrantDestination(grant, item.DestinationPath); err != nil {
			return job.BytesCompleted, err
		}
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
		if filtered {
			// Re-judge each entry with the current policy: it may have changed
			// since the plan was made.
			if denied := s.itemDenied(ctx, grant.MountID, item, access); denied != "" {
				item.State, item.Error = "failed", denied
				warnings++
				if item.Type == "file" {
					filesFailed++
				}
				if err := s.store.UpdateJobItem(ctx, item); err != nil {
					return bytesCompleted, err
				}
				continue
			}
		}
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
	if warnings > 0 || job.SourcesOmitted > 0 {
		if job.SourcesOmitted > 0 {
			return bytesCompleted, jobs.WarningFor(warnings, job.SourcesOmitted)
		}
		return bytesCompleted, fmt.Errorf("%w: %d remote item(s) could not be copied", jobs.ErrWarnings, warnings)
	}
	if job.Type == "transfer_move_batch" {
		latest, latestErr := s.store.ListJobItems(ctx, job.ID)
		if latestErr != nil {
			return bytesCompleted, latestErr
		}
		currentPeer, validationErr := s.trustedPeer(ctx, job.PeerNodeID)
		if validationErr != nil {
			return bytesCompleted, validationErr
		}
		currentGrant, validationErr := s.receiveGrant(ctx, currentPeer.NodeID, job.DestinationGrantID, job.ConflictPolicy)
		if validationErr != nil {
			return bytesCompleted, validationErr
		}
		if currentGrant.MountID != job.MountID {
			return bytesCompleted, ErrForbidden
		}
		for _, item := range latest {
			if err := validateGrantDestination(currentGrant, item.DestinationPath); err != nil {
				return bytesCompleted, err
			}
			if item.Action == "skip" && job.ConflictPolicy != "checksum" {
				return bytesCompleted, fmt.Errorf("%w: source was preserved because an existing destination was skipped without checksum verification", jobs.ErrWarnings)
			}
		}
		job.Phase, job.UpdatedAt = "finalizing", time.Now().UTC()
		if err := s.store.UpdateJob(ctx, job); err != nil {
			return bytesCompleted, err
		}
		if err := s.cleanupMovedSources(ctx, peer, job, latest); err != nil {
			return bytesCompleted, err
		}
	}
	return bytesCompleted, nil
}

func (s *Service) cleanupMovedSources(ctx context.Context, peer entities.Peer, job entities.Job, items []entities.JobItem) error {
	// Check every selected root before deleting any individual source item.
	// An older peer cannot attest to this check, so it is rejected rather than
	// silently allowing a partially moved tree.
	rootCount := 0
	for _, item := range items {
		if !item.SourceRoot {
			continue
		}
		rootCount++
		if item.SourceCleanupState == "completed" {
			continue
		}
		if err := s.validateRemoteMoveSource(ctx, peer, job.SourceGrantID, item.SourcePath); err != nil {
			return err
		}
	}
	if rootCount == 0 {
		return fmt.Errorf("%w: move source roots are unavailable; replan the transfer", ErrInvalid)
	}
	itemsToRemove := make([]entities.JobItem, 0)
	for _, item := range items {
		if item.SourceCleanupState != "completed" {
			itemsToRemove = append(itemsToRemove, item)
		}
	}
	sort.Slice(itemsToRemove, func(left, right int) bool {
		if itemsToRemove[left].Type != itemsToRemove[right].Type {
			return itemsToRemove[left].Type == "file"
		}
		return strings.Count(itemsToRemove[left].SourcePath, "/") > strings.Count(itemsToRemove[right].SourcePath, "/")
	})
	for _, item := range itemsToRemove {
		root := ""
		foundRoot := false
		for _, candidate := range items {
			if !candidate.SourceRoot {
				continue
			}
			base, child := cleanRelative(candidate.SourcePath), cleanRelative(item.SourcePath)
			if base == "." || child == base || strings.HasPrefix(child, base+"/") {
				root, foundRoot = candidate.SourcePath, true
				break
			}
		}
		if !foundRoot {
			return fmt.Errorf("%w: move item has no selected root", ErrInvalid)
		}
		if access, filtered := jobs.TransferAccessFrom(ctx); filtered && !access.Source.AllowsEntryCapability(access.SourceMountPath(item.SourcePath), item.Type, "delete") {
			// Never delete what the lease does not let the actor delete.
			item.SourceCleanupState, item.Error, item.UpdatedAt = "failed", "the source is no longer permitted", time.Now().UTC()
			_ = s.store.UpdateJobItem(context.Background(), item)
			return ErrForbidden
		}
		expectedETag := sourceEntryETag(item)
		if item.Type == "directory" {
			// Deleting descendants updates the directory mtime by design. A
			// non-recursive delete still fails if a new or changed child remains.
			expectedETag = ""
		}
		if err := s.deleteRemoteSource(ctx, peer, job.SourceGrantID, item.SourcePath, root, expectedETag, false); err != nil {
			item.SourceCleanupState, item.Error, item.UpdatedAt = "failed", err.Error(), time.Now().UTC()
			_ = s.store.UpdateJobItem(context.Background(), item)
			return err
		}
		item.SourceCleanupState, item.Error, item.UpdatedAt = "completed", "", time.Now().UTC()
		if err := s.store.UpdateJobItem(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ValidateMoveSource(ctx context.Context, peerNodeID, grantID, relative string) error {
	grant, err := s.sendGrant(ctx, peerNodeID, grantID)
	if err != nil {
		return err
	}
	if !grant.Permissions.Delete {
		return ErrForbidden
	}
	sourcePath, err := withinGrantWithExclusions(grant, relative)
	if err != nil {
		return err
	}
	return s.files.ValidateMoveSourceWithExclusions(ctx, grant.MountID, sourcePath, grant.Exclude)
}

func (s *Service) validateRemoteMoveSource(ctx context.Context, peer entities.Peer, grantID, relative string) error {
	endpoint, err := url.Parse(strings.TrimRight(peer.MTLSEndpoint, "/"))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return fmt.Errorf("%w: invalid peer mTLS endpoint", ErrPeer)
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/peer/v1/grants/" + url.PathEscape(grantID) + "/actions/validate-move"
	body, err := json.Marshal(map[string]string{"path": relative})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.doPeerRequest(peer, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return filesystem.ErrProtectedTree
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		var payload struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&payload) == nil && payload.Error.Code == "source_not_found" {
			return filesystem.ErrNotFound
		}
		return ErrPeerUpgradeRequired
	case http.StatusMethodNotAllowed:
		return ErrPeerUpgradeRequired
	default:
		return fmt.Errorf("%w: move validation returned HTTP %d", ErrPeer, response.StatusCode)
	}
}

func (s *Service) DeleteSource(ctx context.Context, peerNodeID, grantID, relative string, sourceRoot *string, expectedETag string, recursive bool) error {
	if recursive {
		return ErrForbidden
	}
	grant, err := s.sendGrant(ctx, peerNodeID, grantID)
	if err != nil {
		return err
	}
	if !grant.Permissions.Delete {
		return ErrForbidden
	}
	sourcePath, err := withinGrantWithExclusions(grant, relative)
	if err != nil {
		return err
	}
	if sourceRoot == nil {
		return ErrPeerUpgradeRequired
	}
	rootPath, err := withinGrantWithExclusions(grant, *sourceRoot)
	if err != nil {
		return err
	}
	if rootPath != "." && sourcePath != rootPath && !strings.HasPrefix(sourcePath, rootPath+"/") {
		return ErrForbidden
	}
	if err := s.files.ValidateMoveSourceWithExclusions(ctx, grant.MountID, rootPath, grant.Exclude); err != nil {
		return err
	}
	entry, err := s.files.Metadata(ctx, grant.MountID, sourcePath)
	if err != nil {
		return err
	}
	if expectedETag != "" && sourceEntryETag(entities.JobItem{Size: entry.Size, ModifiedAt: entry.ModifiedAt}) != expectedETag {
		return filesystem.ErrSourceChanged
	}
	return s.files.Delete(ctx, grant.MountID, sourcePath, recursive)
}

func (s *Service) deleteRemoteSource(ctx context.Context, peer entities.Peer, grantID, relative, sourceRoot, expectedETag string, recursive bool) error {
	endpoint, err := url.Parse(strings.TrimRight(peer.MTLSEndpoint, "/"))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return fmt.Errorf("%w: invalid peer mTLS endpoint", ErrPeer)
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/peer/v1/grants/" + url.PathEscape(grantID) + "/actions/delete"
	body, err := json.Marshal(map[string]any{"path": relative, "source_root": sourceRoot, "expected_etag": expectedETag, "recursive": recursive})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.doPeerRequest(peer, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusPreconditionFailed:
		return filesystem.ErrSourceChanged
	case http.StatusConflict:
		return filesystem.ErrProtectedTree
	default:
		return fmt.Errorf("remote source cleanup returned HTTP %d", response.StatusCode)
	}
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

func (s *Service) planRemoteAction(ctx context.Context, grant entities.TransferPathGrant, item entities.JobItem, policy string) (string, string, error) {
	mountID := grant.MountID
	hidden, err := s.files.IsHiddenPath(ctx, mountID, item.DestinationPath)
	if err != nil {
		return "", item.DestinationPath, err
	}
	if hidden {
		return "", item.DestinationPath, filesystem.ErrHiddenName
	}
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
		destination, err := s.uniqueDestination(ctx, grant, item.DestinationPath)
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
	if errors.Is(err, contracts.ErrNotFound) || (err == nil && !entities.TrustedPeerState(peer.State)) {
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
	if errors.Is(err, contracts.ErrNotFound) {
		return grant, ErrForbidden
	}
	if err != nil {
		return grant, err
	}
	if !grant.Enabled || grant.PeerNodeID != peerNodeID ||
		(grant.Direction != "send" && grant.Direction != "send_receive") || !grant.Permissions.Read {
		return grant, ErrForbidden
	}
	if filepolicy.ValidatePatterns(grant.Exclude) != nil {
		return grant, ErrForbidden
	}
	if err := s.refuseLockedMount(ctx, grant); err != nil {
		return grant, err
	}
	return grant, nil
}

// refuseLockedMount keeps a locked mount out of every transfer, even when a
// grant for it still exists. Grants on a locked mount are also reported inactive.
func (s *Service) refuseLockedMount(ctx context.Context, grant entities.TransferPathGrant) error {
	locked, err := s.files.IsLocked(ctx, grant.MountID)
	if err != nil {
		return err
	}
	if locked {
		return fmt.Errorf("%w: the mount is locked", ErrForbidden)
	}
	return nil
}

func (s *Service) receiveGrant(ctx context.Context, peerNodeID, grantID, policy string) (entities.TransferPathGrant, error) {
	grant, err := s.store.GetTransferGrant(ctx, strings.TrimSpace(grantID))
	if errors.Is(err, contracts.ErrNotFound) {
		return grant, ErrForbidden
	}
	if err != nil {
		return grant, err
	}
	if !grant.Enabled || grant.PeerNodeID != peerNodeID ||
		(grant.Direction != "receive" && grant.Direction != "send_receive") || !grant.Permissions.Write {
		return grant, ErrForbidden
	}
	if filepolicy.ValidatePatterns(grant.Exclude) != nil {
		return grant, ErrForbidden
	}
	if policy = normalizePolicy(policy); !contains(grant.ConflictPolicies, policy) {
		return grant, fmt.Errorf("%w: conflict policy is not allowed by the destination grant", ErrForbidden)
	}
	if err := s.refuseLockedMount(ctx, grant); err != nil {
		return grant, err
	}
	return grant, nil
}

func (s *Service) receiveDestination(ctx context.Context, peerNodeID, grantID, relative, policy string) (entities.TransferPathGrant, string, error) {
	grant, err := s.receiveGrant(ctx, peerNodeID, grantID, policy)
	if err != nil {
		return grant, "", err
	}
	destination, err := withinGrantWithExclusions(grant, relative)
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

func (s *Service) uniqueDestination(ctx context.Context, grant entities.TransferPathGrant, destination string) (string, error) {
	mountID := grant.MountID
	extension := path.Ext(destination)
	base := strings.TrimSuffix(destination, extension)
	for index := 1; index <= 10_000; index++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, index, extension)
		if err := validateGrantDestination(grant, candidate); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return "", err
		}
		hidden, err := s.files.IsHiddenPath(ctx, mountID, candidate)
		if err != nil {
			return "", err
		}
		if hidden {
			continue
		}
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

func withinGrantWithExclusions(grant entities.TransferPathGrant, relative string) (string, error) {
	resolved, err := withinGrant(grant.Path, relative)
	if err != nil {
		return "", err
	}
	if err := validateGrantDestination(grant, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func validateGrantDestination(grant entities.TransferPathGrant, destination string) error {
	if path.IsAbs(destination) || strings.Contains(destination, "\\") {
		return filesystem.ErrTraversal
	}
	resolved := cleanRelative(destination)
	base := cleanRelative(grant.Path)
	if resolved == ".." || strings.HasPrefix(resolved, "../") || base != "." && resolved != base && !strings.HasPrefix(resolved, base+"/") {
		return filesystem.ErrTraversal
	}
	for _, component := range strings.Split(resolved, "/") {
		if component != "." && filepolicy.Hidden(grant.Exclude, component) {
			return ErrForbidden
		}
	}
	return nil
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

// checkDestinationAccess confirms the signed policy lets the actor write the
// item's final destination. Items that will not be written need no check.
func (s *Service) checkDestinationAccess(ctx context.Context, mountID string, item entities.JobItem, access *jobs.TransferAccess) error {
	switch item.Action {
	case "copy", "overwrite", "rename", "create":
	default:
		return nil
	}
	_, _, err := s.files.InspectCopyDestinationFiltered(ctx, mountID, item.DestinationPath, item.Type, access.Destination)
	return err
}

// signedTransferAccess builds the filters of a lease for a node-to-node copy.
func signedTransferAccess(filter *filetypes.Filter, binding signedauth.Binding) (jobs.TransferAccess, error) {
	destination, err := filesystem.NewAccessFilter(filter, "nodes/"+binding.DestinationNodeID+"/files/mounts/"+binding.DestinationMountID)
	if err != nil {
		return jobs.TransferAccess{}, ErrInvalid
	}
	source, err := filesystem.NewAccessFilter(filter, "nodes/"+binding.SourceNodeID+"/files/mounts/"+binding.SourceMountID)
	if err != nil {
		return jobs.TransferAccess{}, ErrInvalid
	}
	return jobs.TransferAccess{Destination: destination, Source: source, SourceRoot: binding.SourceRoot}, nil
}

func (s *Service) signedBatchJobRequest(ctx context.Context, request BatchPullRequest, sourceRoot, destinationMount string) (jobs.CreateRequest, string, error) {
	operation := strings.ToLower(strings.TrimSpace(request.Operation))
	if operation == "" {
		operation = "copy"
	}
	if operation != "copy" && operation != "move" {
		return jobs.CreateRequest{}, "", fmt.Errorf("%w: operation must be copy or move", ErrInvalid)
	}
	typeName := "transfer_pull_batch"
	if operation == "move" {
		typeName = "transfer_move_batch"
	}
	destinationGrant, destinationBase, err := s.receiveDestination(ctx, strings.TrimSpace(request.PeerNodeID), request.DestinationGrantID, request.DestinationPath, request.ConflictPolicy)
	if err != nil {
		return jobs.CreateRequest{}, "", err
	}
	if destinationMount != "" && destinationGrant.MountID != destinationMount {
		return jobs.CreateRequest{}, "", ErrForbidden
	}
	if destinationBase == "" {
		destinationBase = "."
	}
	return jobs.CreateRequest{
		Type: typeName, MountID: destinationGrant.MountID, PeerNodeID: strings.TrimSpace(request.PeerNodeID),
		SourceGrantID: strings.TrimSpace(request.SourceGrantID), DestinationGrantID: strings.TrimSpace(request.DestinationGrantID),
		SourcePath: sourceRoot, Destination: destinationBase, ConflictPolicy: normalizePolicy(request.ConflictPolicy),
		VerifyChecksum: request.VerifyChecksum, BandwidthLimit: request.BandwidthLimit, MaxParallelFiles: request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks, CorrelationID: request.CorrelationID,
	}, destinationBase, nil
}

// PrepareSignedBatchPull normalizes a node-to-node copy into the immutable
// options a lease binds, without planning or creating anything.
func (s *Service) PrepareSignedBatchPull(ctx context.Context, request BatchPullRequest) (signedauth.JobOptions, string, error) {
	jobRequest, _, err := s.signedBatchJobRequest(ctx, request, ".", "")
	if err != nil {
		return signedauth.JobOptions{}, "", err
	}
	return s.jobs.PrepareSignedBatchPull(jobRequest)
}

// ErrMoveIncomplete means a move cannot proceed because part of the selection is
// hidden from the actor: moving deletes the source, so it needs all of it.
var ErrMoveIncomplete = errors.New("a move needs access to every selected entry")

// signedBatchPlan is a node-to-node copy or move planned under a verified lease.
type signedBatchPlan struct {
	binding         signedauth.Binding
	request         jobs.CreateRequest
	destinationBase string
	plan            entities.CopyPlan
	omitted         int
	move            bool
}

// planSignedBatch verifies the lease and plans the transfer under its filter.
// Source entries the filter hides are left out and counted for a copy; a move
// refuses them, since it deletes the source afterwards. A destination the policy
// does not let the actor write fails the whole plan.
func (s *Service) planSignedBatch(ctx context.Context, request BatchPullRequest, nodeID, envelope string, keys map[string]ed25519.PublicKey) (signedBatchPlan, error) {
	now := time.Now().UTC()
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
	if err != nil || binding.DestinationNodeID != nodeID || binding.SourceNodeID != strings.TrimSpace(request.PeerNodeID) ||
		binding.SourceGrantID != strings.TrimSpace(request.SourceGrantID) || binding.DestinationGrantID != strings.TrimSpace(request.DestinationGrantID) || binding.JobOptionsDigest == "" {
		return signedBatchPlan{}, ErrInvalid
	}
	move := strings.ToLower(strings.TrimSpace(request.Operation)) == "move"
	if (move && binding.Operation != "transfer_move_batch") || (!move && binding.Operation != "transfer_pull_batch") {
		return signedBatchPlan{}, ErrInvalid
	}
	_, filter, err := signedauth.VerifyJobLease(envelope, keys, binding, nodeID, 1, now)
	if err != nil {
		return signedBatchPlan{}, ErrInvalid
	}
	jobRequest, destinationBase, err := s.signedBatchJobRequest(ctx, request, binding.SourceRoot, binding.DestinationMountID)
	if err != nil {
		return signedBatchPlan{}, err
	}
	if binding.DestinationRoot != destinationBase {
		return signedBatchPlan{}, ErrInvalid
	}
	access, err := signedTransferAccess(filter, binding)
	if err != nil {
		return signedBatchPlan{}, err
	}
	plan, omitted, err := s.planBatch(ctx, request, &access)
	if err != nil {
		return signedBatchPlan{}, err
	}
	if move && omitted > 0 {
		return signedBatchPlan{}, ErrMoveIncomplete
	}
	plan.DestinationPath, plan.SourcesOmitted = destinationBase, omitted
	return signedBatchPlan{binding: binding, request: jobRequest, destinationBase: destinationBase, plan: plan, omitted: omitted, move: move}, nil
}

// movePlanDigest identifies exactly what a move would do: the actor, both
// endpoints, the policy and every planned entry with its size, time, checksum
// and action. A confirmation only counts if a fresh plan has the same digest.
func movePlanDigest(binding signedauth.Binding, plan entities.CopyPlan) string {
	hash := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			_, _ = hash.Write([]byte(part))
			_, _ = hash.Write([]byte{0})
		}
	}
	write("jolt-transfer-move-plan-v1", binding.ActorID, binding.SourceNodeID, binding.SourceGrantID, binding.SourceMountID, binding.SourceRoot,
		binding.DestinationNodeID, binding.DestinationGrantID, binding.DestinationMountID, binding.DestinationRoot, binding.JobOptionsDigest, plan.ConflictPolicy)
	items := append([]entities.JobItem(nil), plan.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].SourcePath < items[j].SourcePath })
	for _, item := range items {
		write(item.SourcePath, item.DestinationPath, item.Type, strconv.FormatInt(item.Size, 10), strconv.FormatInt(item.ModifiedAt.UnixNano(), 10), item.Checksum, item.Action, strconv.FormatBool(item.SourceRoot))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// PlanSignedBatchPull previews a node-to-node copy or move under a signed lease
// without creating a job. The preview only carries entries the policy lets the
// actor list and read; omitted ones are counted, never named. A move preview
// also records its one-use confirmation, which a later creation must present.
func (s *Service) PlanSignedBatchPull(ctx context.Context, request BatchPullRequest, nodeID, envelope string, keys map[string]ed25519.PublicKey) (entities.CopyPlan, error) {
	planned, err := s.planSignedBatch(ctx, request, nodeID, envelope, keys)
	if err != nil {
		return entities.CopyPlan{}, err
	}
	if planned.move {
		confirmation, err := s.jobs.CreateTransferMovePlan(ctx, request.SubjectType, planned.binding.ActorID, planned.request.MountID, movePlanDigest(planned.binding, planned.plan))
		if err != nil {
			return entities.CopyPlan{}, err
		}
		planned.plan.MovePlan = &confirmation
	}
	return planned.plan, nil
}

// CreateSignedBatchPull plans a node-to-node copy or move under the filter of a
// signed, job-bound lease and persists the job awaiting that authorization. A
// move must present the confirmation of a plan with the same digest.
func (s *Service) CreateSignedBatchPull(ctx context.Context, request BatchPullRequest, nodeID, envelope, idempotencyKey string, keys map[string]ed25519.PublicKey) (entities.Job, bool, error) {
	now := time.Now().UTC()
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
	if err != nil || binding.JobOptionsDigest == "" {
		return entities.Job{}, false, ErrInvalid
	}
	// A repeated request returns its job without fetching the manifest again.
	hash, err := jobs.SignedBatchPullHash(binding)
	if err != nil {
		return entities.Job{}, false, ErrInvalid
	}
	if existing, storedHash, found, err := s.store.FindJobByIdempotency(ctx, idempotencyKey); err != nil {
		return entities.Job{}, false, err
	} else if found {
		if storedHash != hash || !existing.RequiresSignedAuth {
			return entities.Job{}, false, contracts.ErrIdempotencyConflict
		}
		return existing, true, nil
	}
	planned, err := s.planSignedBatch(ctx, request, nodeID, envelope, keys)
	if err != nil {
		return entities.Job{}, false, err
	}
	var confirmation *jobs.MoveConfirmation
	if planned.move {
		if request.MovePlanID == "" || request.MovePlanToken == "" || request.SubjectType == "" {
			return entities.Job{}, false, jobs.ErrPlanRejected
		}
		confirmation = &jobs.MoveConfirmation{PlanID: request.MovePlanID, SubjectType: request.SubjectType, Token: request.MovePlanToken, Digest: movePlanDigest(planned.binding, planned.plan)}
	}
	job, repeated, err := s.jobs.CreateSignedPlannedBatchPull(ctx, planned.request, planned.plan, planned.omitted, nodeID, envelope, idempotencyKey, keys, confirmation)
	if err != nil && planned.move && errors.Is(err, contracts.ErrInUse) {
		// The plan was not found, belongs to someone else, expired, was used, or
		// no longer matches what is on disk. One answer for all of them.
		return entities.Job{}, false, jobs.ErrTreeChanged
	}
	return job, repeated, err
}

// itemDenied explains, without naming any path, why the current policy no
// longer lets a planned item run; it returns an empty string when it does.
func (s *Service) itemDenied(ctx context.Context, mountID string, item entities.JobItem, access jobs.TransferAccess) string {
	if !access.Source.AllowsListedEntry(access.SourceMountPath(item.SourcePath), item.Type) {
		return "the source is no longer permitted"
	}
	switch item.Action {
	case "copy", "overwrite", "rename", "create":
		if err := s.checkDestinationAccess(ctx, mountID, item, &access); err != nil {
			return "the destination is no longer permitted"
		}
	}
	return ""
}

package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/buildinfo"
	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/config"
	joltcrypto "github.com/jfxdev/jolt/backend/internal/infra/crypto"

	"github.com/jfxdev/jolt/backend/internal/infra/metrics"
	"github.com/jfxdev/jolt/backend/internal/services/filesystem"
	"github.com/jfxdev/jolt/backend/internal/services/grants"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/services/pairing"
	"github.com/jfxdev/jolt/backend/internal/services/transfers"
)

type Server struct {
	uploadAdmission sync.Mutex
	config          config.Config
	store           contracts.Store
	identity        entities.Identity
	files           *filesystem.Service
	jobs            *jobs.Service
	pairing         *pairing.Service
	grants          *grants.Service
	certificates    *joltcrypto.CertificateManager
	transfers       *transfers.Service
	registry        *metrics.Registry
	log             *slog.Logger
}

const editorMaxBytes int64 = 512 * 1024

func New(cfg config.Config, identity entities.Identity, files *filesystem.Service, jobService *jobs.Service, pairingService *pairing.Service, grantService *grants.Service, logger *slog.Logger, dependencies ...any) http.Handler {
	if cfg.UploadMaxBytes <= 0 {
		cfg.UploadMaxBytes = filesystem.DefaultMaxUploadBytes
	}
	if cfg.UploadMaxSessions <= 0 {
		cfg.UploadMaxSessions = 32
	}
	if cfg.UploadMaxReservedBytes <= 0 {
		cfg.UploadMaxReservedBytes = 400 << 30
	}
	if cfg.UploadSessionTTL <= 0 {
		cfg.UploadSessionTTL = 24 * time.Hour
	}
	if cfg.CopyChunkSize <= 0 {
		cfg.CopyChunkSize = 16 << 20
	}
	files.ConfigureUploadLimits(cfg.UploadMaxBytes, cfg.UploadMinFreeBytes)
	files.ConfigureUploadInspection(filesystem.UploadInspection{Enabled: cfg.UploadInspection.Enabled, BlockExecutables: cfg.UploadInspection.BlockExecutables, AllowedMediaTypes: cfg.UploadInspection.AllowedMediaTypes})
	s := &Server{config: cfg, identity: identity, files: files, jobs: jobService, pairing: pairingService, grants: grantService, log: logger}
	for _, dependency := range dependencies {
		switch value := dependency.(type) {
		case *metrics.Registry:
			s.registry = value
		case *joltcrypto.CertificateManager:
			s.certificates = value
		case *transfers.Service:
			s.transfers = value
		case contracts.Store:
			s.store = value
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /livez", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /openapi.yaml", s.openapi)
	mux.HandleFunc("GET /docs", s.swagger)
	mux.HandleFunc("GET /api/v1/node", s.node)
	mux.HandleFunc("GET /api/v1/config/effective", s.effectiveConfig)
	mux.HandleFunc("GET /api/v1/fs/browse", s.browseFilesystem)
	mux.HandleFunc("GET /api/v1/mounts", s.listMounts)
	mux.HandleFunc("POST /api/v1/mounts", s.createMount)
	mux.HandleFunc("GET /api/v1/mounts/{mountID}", s.getMount)
	mux.HandleFunc("PUT /api/v1/mounts/{mountID}", s.updateMount)
	mux.HandleFunc("DELETE /api/v1/mounts/{mountID}", s.deleteMount)
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files", s.signedLocalRead("list", s.listFiles))
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/metadata", s.signedLocalRead("metadata", s.metadata))
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/content", s.signedLocalRead("content", s.download))
	mux.HandleFunc("PUT /api/v1/mounts/{mountID}/files/content", s.signedUpload("upload_simple", s.upload))
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/archive", s.signedLocalRead("archive", s.archive))
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/archive/plan", s.signedLocalRead("archive_plan", s.archivePlan))
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/search", s.signedLocalRead("search", s.search))
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/disk-usage", s.signedLocalRead("disk_usage", s.diskUsage))
	mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/directories", s.mkdir)
	mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/copy/plan", s.planCopy)
	mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/copy", s.copy)
	mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/move", s.move)
	mux.HandleFunc("DELETE /api/v1/mounts/{mountID}/files", s.deleteFile)
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/trash", s.listTrash)
	mux.HandleFunc("GET /api/v1/mounts/{mountID}/trash/{trashID}", s.getTrash)
	mux.HandleFunc("POST /api/v1/mounts/{mountID}/trash/{trashID}/restore", s.restoreTrash)
	mux.HandleFunc("DELETE /api/v1/mounts/{mountID}/trash/{trashID}", s.purgeTrash)
	if s.store != nil {
		mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/uploads", s.listUploadSessions)
		mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/uploads", s.signedUpload("upload_create", s.createUploadSession))
		mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/uploads/{uploadID}/verification", s.uploadLocked(s.verifyUploadSession))
		mux.HandleFunc("GET /api/v1/mounts/{mountID}/files/uploads/{uploadID}", s.uploadLocked(s.getUploadSession))
		mux.HandleFunc("PATCH /api/v1/mounts/{mountID}/files/uploads/{uploadID}", s.uploadLocked(s.signedUpload("upload_chunk", s.appendUploadChunk)))
		mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/uploads/{uploadID}/complete", s.uploadLocked(s.signedUpload("upload_complete", s.completeUploadSession)))
		mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/uploads/{uploadID}/authorize", s.uploadLocked(s.signedUpload("upload_reauthorize", s.reauthorizeUploadSession)))
		mux.HandleFunc("DELETE /api/v1/mounts/{mountID}/files/uploads/{uploadID}", s.uploadLocked(s.signedUpload("upload_abort", s.abortUploadSession)))
	}
	mux.HandleFunc("GET /api/v1/jobs", s.listJobs)
	mux.HandleFunc("GET /api/v1/jobs/summary", s.jobSummary)
	mux.HandleFunc("GET /api/v1/jobs/events", s.streamJobEvents)
	mux.HandleFunc("GET /api/v1/jobs/{jobID}", s.getJob)
	if _, ok := s.store.(signedJobCreationStore); ok && s.jobs != nil {
		mux.HandleFunc("POST /api/v1/jobs/signed-local-copy/prepare", s.prepareSignedLocalCopy)
		mux.HandleFunc("POST /api/v1/jobs/signed-local-copy", s.createSignedLocalCopy)
	}
	if _, ok := s.store.(jobs.DestructivePlanStore); ok && s.jobs != nil {
		mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/destructive-plans", s.createDestructivePlan)
		mux.HandleFunc("POST /api/v1/mounts/{mountID}/files/destructive-plans/{planID}/accept", s.acceptDestructivePlan)
	}
	if _, ok := s.store.(signedJobAuthorizationRegistrar); ok {
		mux.HandleFunc("POST /api/v1/jobs/{jobID}/authorization", s.registerJobAuthorization)
	}
	if _, ok := s.store.(signedJobAuthorizationReporter); ok {
		mux.HandleFunc("GET /api/v1/jobs/{jobID}/authorization", s.jobAuthorizationStatus)
	}
	mux.HandleFunc("GET /api/v1/jobs/{jobID}/items", s.listJobItems)
	mux.HandleFunc("POST /api/v1/jobs/{jobID}/items/{ordinal}/override", s.overrideJobItem)
	mux.HandleFunc("POST /api/v1/jobs/{jobID}/pause", s.pauseJob)
	mux.HandleFunc("POST /api/v1/jobs/{jobID}/resume", s.resumeJob)
	mux.HandleFunc("POST /api/v1/jobs/{jobID}/cancel", s.cancelJob)
	mux.HandleFunc("POST /api/v1/jobs/{jobID}/retry", s.retryJob)
	mux.HandleFunc("GET /api/v1/pairing/invites", s.listPairingInvites)
	mux.HandleFunc("POST /api/v1/pairing/invites", s.createPairingInvite)
	mux.HandleFunc("DELETE /api/v1/pairing/invites/{inviteID}", s.revokePairingInvite)
	mux.HandleFunc("POST /api/v1/pairing/invites/{inviteID}/approve", s.approvePairingInvite)
	mux.HandleFunc("GET /api/v1/pairing/requests", s.listPairingRequests)
	mux.HandleFunc("POST /api/v1/pairing/requests", s.createPairingRequest)
	mux.HandleFunc("POST /api/v1/pairing/requests/{requestID}/accept", s.acceptPairingRequest)
	mux.HandleFunc("POST /api/v1/pairing/requests/{requestID}/reject", s.rejectPairingRequest)
	mux.HandleFunc("GET /api/v1/peers", s.listPeers)
	mux.HandleFunc("PATCH /api/v1/peers/{peerNodeID}", s.updatePeerEndpoints)
	mux.HandleFunc("PATCH /api/v1/peers/{peerNodeID}/identity", s.recoverPeerIdentity)
	mux.HandleFunc("PATCH /api/v1/peers/{peerNodeID}/identity/handover", s.applyPeerIdentityHandover)
	mux.HandleFunc("PATCH /api/v1/peers/{peerNodeID}/mtls/rollout", s.acceptPeerMTLSRollout)
	mux.HandleFunc("DELETE /api/v1/peers/{peerNodeID}", s.revokePeer)
	mux.HandleFunc("GET /api/v1/grants", s.listGrants)
	mux.HandleFunc("POST /api/v1/grants", s.createGrant)
	mux.HandleFunc("PATCH /api/v1/grants/{grantID}", s.updateGrant)
	mux.HandleFunc("DELETE /api/v1/grants/{grantID}", s.deleteGrant)
	if s.certificates != nil {
		mux.HandleFunc("GET /api/v1/crypto/identity", s.identityState)
		mux.HandleFunc("GET /api/v1/crypto/identity/handovers", s.identityHandovers)
		mux.HandleFunc("POST /api/v1/crypto/identity/rotate", s.rotateIdentity)
		mux.HandleFunc("GET /api/v1/crypto/mtls", s.mtlsState)
		mux.HandleFunc("GET /api/v1/crypto/mtls/rollout", s.mtlsRolloutEnvelope)
		mux.HandleFunc("POST /api/v1/crypto/mtls/rollout/deliveries", s.recordMTLSRolloutDelivery)
		mux.HandleFunc("POST /api/v1/crypto/mtls/rotate", s.prepareMTLSRotation)
		mux.HandleFunc("POST /api/v1/crypto/mtls/promote", s.promoteMTLSRotation)
		mux.HandleFunc("POST /api/v1/crypto/mtls/rollback", s.rollbackMTLSRotation)
		mux.HandleFunc("POST /api/v1/crypto/mtls/revoke", s.revokeMTLSCertificate)
	}
	if s.store != nil {
		mux.HandleFunc("GET /api/v1/crypto/operational-token", s.operationalTokenState)
		mux.HandleFunc("POST /api/v1/crypto/operational-token/prepare", s.prepareOperationalToken)
		mux.HandleFunc("POST /api/v1/crypto/operational-token/commit", s.commitOperationalToken)
	}
	if s.transfers != nil {
		mux.HandleFunc("POST /api/v1/transfers/pull", s.createPullTransfer)
		mux.HandleFunc("POST /api/v1/transfers/pull/directory/plan", s.planDirectoryPullTransfer)
		mux.HandleFunc("POST /api/v1/transfers/pull/directory", s.createDirectoryPullTransfer)
		mux.HandleFunc("POST /api/v1/transfers/pull/batch/plan", s.planBatchPullTransfer)
		mux.HandleFunc("POST /api/v1/transfers/pull/batch", s.createBatchPullTransfer)
		mux.HandleFunc("POST /api/v1/transfers/signed-pull/batch/prepare", s.prepareSignedBatchPull)
		mux.HandleFunc("POST /api/v1/transfers/signed-pull/batch/plan", s.planSignedBatchPull)
		mux.HandleFunc("POST /api/v1/transfers/signed-pull/batch", s.createSignedBatchPull)
	}
	if s.registry != nil && s.config.MetricsToken != "" {
		mux.HandleFunc("GET /metrics", s.metrics)
	}
	return s.recover(s.correlation(s.logging(s.instrument(s.auth(s.guardSignedContext(mux))))))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.PublicHealth && (r.URL.Path == "/health" || r.URL.Path == "/livez" || r.URL.Path == "/readyz") {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, prefix)
		// /metrics carries its own token so a Prometheus scraper never holds
		// the operational token, which can write to every mount.
		if r.URL.Path == "/metrics" && s.config.MetricsToken != "" {
			if !strings.HasPrefix(header, prefix) || !secureEqual(token, s.config.MetricsToken) {
				writeError(w, r, http.StatusUnauthorized, "unauthorized", "A valid metrics token is required.", nil)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(header, prefix) || !s.acceptOperationalToken(r.Context(), token) {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "A valid bearer token is required.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// instrument records request counts and latency. The route label is the
// matched pattern, never the raw path: a label per file path would blow up
// Prometheus cardinality on a mount with thousands of files.
func (s *Server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.registry == nil {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			route := routeLabel(r)
			status := strconv.Itoa(recorder.status)
			s.registry.Inc("jolt_http_requests_total", r.Method, route, status)
			s.registry.ObserveDuration("jolt_http_request_duration_seconds", start, route)
			s.registry.Add("jolt_http_response_bytes_total", recorder.written, route)
		}()
		next.ServeHTTP(recorder, r)
	})
}

// routeLabel reduces a request to a bounded set of label values.
func routeLabel(r *http.Request) string {
	if pattern := r.Pattern; pattern != "" {
		if _, path, found := strings.Cut(pattern, " "); found {
			return path
		}
		return pattern
	}
	return "unmatched"
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusRecorder) WriteHeader(status int) {
	if !w.wrote {
		w.status, w.wrote = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(data []byte) (int, error) {
	w.wrote = true
	count, err := w.ResponseWriter.Write(data)
	w.written += int64(count)
	return count, err
}

// Flush keeps SSE and streamed archives working through the recorder.
func (w *statusRecorder) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Server) acceptOperationalToken(ctx context.Context, token string) bool {
	if token == "" {
		return false
	}
	if s.store == nil {
		return secureEqual(token, s.config.ControlTowerToken)
	}
	state, err := s.store.GetOperationalTokenState(ctx)
	if errors.Is(err, contracts.ErrNotFound) {
		return secureEqual(token, s.config.ControlTowerToken)
	}
	if err != nil {
		return false
	}
	digest := operationalTokenDigest(token)
	if state.StagedHash != "" && secureEqual(digest, state.StagedHash) {
		return true
	}
	if state.ActiveHash != "" && secureEqual(digest, state.ActiveHash) {
		return true
	}
	return !state.EnvTokenDisabled && secureEqual(token, s.config.ControlTowerToken)
}

func operationalTokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Correlation-ID"))
		if id == "" {
			id = randomID("cor")
		}
		w.Header().Set("X-Correlation-ID", id)
		r.Header.Set("X-Correlation-ID", id)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "correlation_id", r.Header.Get("X-Correlation-ID"), "duration_ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			value := recover()
			if value == nil {
				return
			}
			// http.ErrAbortHandler is how a handler says "drop this
			// connection". It is raised deliberately when a streamed response
			// such as an archive fails after its headers were already sent:
			// writing a 500 body onto that stream would hand the client a
			// valid-looking but incomplete file instead of a failed transfer.
			// Re-panicking lets net/http close the connection silently.
			if value == http.ErrAbortHandler {
				panic(value)
			}
			s.log.Error("request panic", "error", value, "correlation_id", r.Header.Get("X-Correlation-ID"))
			writeError(w, r, http.StatusInternalServerError, "internal_error", "An unexpected error occurred.", nil)
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "node_id": s.identity.NodeID})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	store, ok := s.store.(interface{ Ready(context.Context) error })
	if !ok || store.Ready(ctx) != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "node_id": s.identity.NodeID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "node_id": s.identity.NodeID})
}

func (s *Server) node(w http.ResponseWriter, r *http.Request) {
	capabilities := []string{"api_filesystem", "streaming_upload", "range_download", "durable_local_jobs", "job_controls", "job_events_sse", "job_eta", "bandwidth_limits", "waiting_mount", "waiting_validation", "directory_manifests", "directory_resume", "resumable_chunks", "conflict_policies", "manual_item_overrides", "checksum_verification", "source_change_policies", "transfer_path_grants", "cluster_grouping", "mtls_peer_listener", "mtls_certificate_rotation", "mtls_certificate_rollout_diagnostics", "mtls_certificate_revocation", "identity_handover", "mtls_peer_heartbeat", "direct_file_pull", "operational_token_rotation", "idempotency", "hidden_patterns_v1", "protected_move_v1", "canary_paths_v1", "agent_search_limits_v1", "agent_secret_scan_v1", "grant_exclude_send_v1", "grant_exclude_receive_v1", "upload_inspection_v1", "trash_v1"}
	if len(s.config.AuthorizationKeys) > 0 {
		capabilities = append(capabilities, "signed_local_read_v1", "signed_local_tree_read_v1")
		if s.store != nil {
			capabilities = append(capabilities, "signed_upload_sessions_v1", "signed_upload_reauthorize_v1", "signed_simple_upload_v1")
		}
		if _, ok := s.store.(signedJobAuthorizationRegistrar); ok {
			capabilities = append(capabilities, "signed_job_authorization_registration_v1", "signed_job_options_binding_v1")
		}
		if _, ok := s.store.(signedJobAuthorizationReporter); ok {
			capabilities = append(capabilities, "signed_job_authorization_status_v1")
		}
		if _, ok := s.store.(signedJobCreationStore); ok && s.jobs != nil {
			capabilities = append(capabilities, "signed_local_copy_creation_v1")
		}
		if s.signedExecutionEnabled() {
			capabilities = append(capabilities, "signed_local_copy_execution_v1")
			if _, ok := s.store.(jobs.DestructivePlanStore); ok {
				capabilities = append(capabilities, "destructive_plans_v1")
			}
			if s.transfers != nil {
				capabilities = append(capabilities, "signed_transfer_pull_v1")
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configuration": map[string]any{"source": "yaml", "apply_mode": "restart", "mounts_mutable": false, "grants_mutable": false},
		"node_id":       s.identity.NodeID, "name": s.config.NodeName, "fingerprint": s.identity.Fingerprint,
		"identity_epoch": s.identity.Epoch, "public_key": s.identity.PublicKey,
		"build":                     buildinfo.Current(),
		"mtls_endpoint":             s.config.MTLSPublicEndpoint,
		"upload_max_bytes":          s.config.UploadMaxBytes,
		"upload_max_sessions":       s.config.UploadMaxSessions,
		"upload_max_reserved_bytes": s.config.UploadMaxReservedBytes,
		"upload_min_free_bytes":     s.config.UploadMinFreeBytes,
		"upload_inspection":         s.config.UploadInspection,
		"state":                     "idle", "capabilities": capabilities,
	})
}

func (s *Server) effectiveConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"configuration":             map[string]any{"source": "yaml", "apply_mode": "restart", "revision": s.config.Revision, "mounts_mutable": false, "grants_mutable": false},
		"upload_max_bytes":          s.config.UploadMaxBytes,
		"upload_max_sessions":       s.config.UploadMaxSessions,
		"upload_max_reserved_bytes": s.config.UploadMaxReservedBytes,
		"upload_min_free_bytes":     s.config.UploadMinFreeBytes,
		"upload_inspection":         s.config.UploadInspection,
		"node_name":                 s.config.NodeName, "api_address": s.config.APIAddress, "mtls_address": s.config.MTLSAddress,
		"mtls_public_endpoint": s.config.MTLSPublicEndpoint,
		"data_dir":             "[internal]", "keys_dir": "[internal]", "control_tower_token": "[redacted]",
		"max_concurrent_jobs": s.config.MaxConcurrentJobs, "job_max_attempts": s.config.JobMaxAttempts,
		"copy_chunk_size_bytes":                 s.config.CopyChunkSize,
		"node_bandwidth_limit_bytes_per_second": s.config.NodeBandwidthLimit,
		"max_parallel_files_per_job":            s.config.MaxParallelFilesPerJob,
		"max_parallel_chunks_per_file":          s.config.MaxParallelChunksPerFile,
		"transfer_connect_timeout":              s.config.TransferConnectTimeout.String(),
		"transfer_idle_read_timeout":            s.config.TransferIdleReadTimeout.String(),
		"transfer_chunk_timeout":                s.config.TransferChunkTimeout.String(),
		"job_validation_timeout":                s.config.JobValidationTimeout.String(),
		"job_no_progress_timeout":               s.config.JobNoProgressTimeout.String(),
		"peer_heartbeat_interval":               s.config.PeerHeartbeatInterval.String(),
		"peer_heartbeat_timeout":                s.config.PeerHeartbeatTimeout.String(),
		"peer_failure_threshold":                s.config.PeerFailureThreshold,
		"locked_fields":                         []string{"api_address", "mtls_address", "data_dir", "keys_dir", "control_tower_token"},
	})
}

func (s *Server) mtlsState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.certificates.Snapshot())
}

func (s *Server) mtlsRolloutEnvelope(w http.ResponseWriter, r *http.Request) {
	envelope, err := s.certificates.NextRolloutEnvelope()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

type mtlsRolloutDeliveryRequest struct {
	Serial        string `json:"serial"`
	PeerNodeID    string `json:"peer_node_id"`
	DeliveryError string `json:"delivery_error"`
}

func (s *Server) recordMTLSRolloutDelivery(w http.ResponseWriter, r *http.Request) {
	var request mtlsRolloutDeliveryRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	rollout, err := s.certificates.RecordRolloutDelivery(request.Serial, request.PeerNodeID,
		request.DeliveryError, r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rollout)
}

func (s *Server) acceptPeerMTLSRollout(w http.ResponseWriter, r *http.Request) {
	var envelope joltcrypto.CertificateRolloutEnvelope
	if !decodeJSON(w, r, &envelope) {
		return
	}
	acceptance, err := s.certificates.AcceptPeerRollout(r.PathValue("peerNodeID"), envelope,
		r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acceptance)
}

func (s *Server) identityState(w http.ResponseWriter, r *http.Request) {
	persisted, err := joltcrypto.LoadOrCreate(s.config.KeysDir)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active": s.identity, "persisted": persisted, "restart_required": persisted != s.identity,
	})
}

type rotateIdentityRequest struct {
	ConfirmedFingerprint string `json:"confirmed_fingerprint"`
}

func (s *Server) rotateIdentity(w http.ResponseWriter, r *http.Request) {
	var request rotateIdentityRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	next, err := joltcrypto.RotateIdentity(s.config.KeysDir, s.identity, request.ConfirmedFingerprint)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	handovers, err := joltcrypto.LoadIdentityHandovers(s.config.KeysDir)
	if err != nil || len(handovers) == 0 {
		s.fail(w, r, errors.New("identity rotated but handover could not be loaded"))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"active": s.identity, "next_active": next, "restart_required": true,
		"handover": handovers[len(handovers)-1],
		"message":  "restart the node to activate the new identity and regenerate mTLS material",
	})
}

func (s *Server) identityHandovers(w http.ResponseWriter, r *http.Request) {
	handovers, err := joltcrypto.LoadIdentityHandovers(s.config.KeysDir)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": handovers})
}

func (s *Server) operationalTokenState(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.GetOperationalTokenState(r.Context())
	if errors.Is(err, contracts.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{
			"rotation_state": "environment", "environment_token_disabled": false,
		})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rotationState := "active"
	if state.StagedHash != "" {
		rotationState = "prepared"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rotation_state": rotationState, "environment_token_disabled": state.EnvTokenDisabled,
		"updated_at": state.UpdatedAt, "correlation_id": state.CorrelationID,
	})
}

type prepareOperationalTokenRequest struct {
	NewToken string `json:"new_token"`
}

func (s *Server) prepareOperationalToken(w http.ResponseWriter, r *http.Request) {
	var request prepareOperationalTokenRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.NewToken) < 32 {
		writeError(w, r, http.StatusBadRequest, "invalid_operational_token",
			"The new operational token must contain at least 32 characters.", nil)
		return
	}
	currentToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if secureEqual(request.NewToken, currentToken) {
		writeError(w, r, http.StatusBadRequest, "operational_token_unchanged",
			"The new operational token must differ from the authenticated token.", nil)
		return
	}
	if err := s.store.StageOperationalToken(r.Context(), operationalTokenDigest(request.NewToken),
		r.Header.Get("X-Correlation-ID"), time.Now().UTC()); err != nil {
		if errors.Is(err, contracts.ErrInUse) {
			writeError(w, r, http.StatusConflict, "token_rotation_in_progress", "Another token rotation is pending.", nil)
			return
		}
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"rotation_state": "prepared"})
}

func (s *Server) commitOperationalToken(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := s.store.CommitOperationalToken(r.Context(), operationalTokenDigest(token),
		r.Header.Get("X-Correlation-ID"), time.Now().UTC()); err != nil {
		if errors.Is(err, contracts.ErrNotFound) {
			writeError(w, r, http.StatusConflict, "operational_token_not_prepared",
				"The authenticated token is not the prepared rotation token.", nil)
			return
		}
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rotation_state": "active", "old_token_invalidated": true})
}

type pullTransferRequest struct {
	PeerNodeID         string `json:"peer_node_id"`
	SourceGrantID      string `json:"source_grant_id"`
	SourcePath         string `json:"source_path"`
	DestinationGrantID string `json:"destination_grant_id"`
	DestinationPath    string `json:"destination_path"`
	ConflictPolicy     string `json:"conflict_policy"`
	VerifyChecksum     bool   `json:"verify_checksum"`
	BandwidthLimit     int64  `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int    `json:"max_parallel_files"`
	MaxParallelChunks  int    `json:"max_parallel_chunks"`
}

type batchPullTransferRequest struct {
	PeerNodeID         string   `json:"peer_node_id"`
	SourceGrantID      string   `json:"source_grant_id"`
	SourcePaths        []string `json:"source_paths"`
	SourceNames        []string `json:"source_names"`
	DestinationGrantID string   `json:"destination_grant_id"`
	DestinationPath    string   `json:"destination_path"`
	Operation          string   `json:"operation"`
	ConflictPolicy     string   `json:"conflict_policy"`
	VerifyChecksum     bool     `json:"verify_checksum"`
	BandwidthLimit     int64    `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int      `json:"max_parallel_files"`
	MaxParallelChunks  int      `json:"max_parallel_chunks"`
	// Used only by signed moves: the authenticated subject the Control Tower
	// names and the confirmation the move consumes.
	SubjectType   string `json:"subject_type"`
	MovePlanID    string `json:"plan_id"`
	MovePlanToken string `json:"plan_token"`
}

func (r batchPullTransferRequest) transferRequest(correlationID string) transfers.BatchPullRequest {
	return transfers.BatchPullRequest{
		PullRequest: transfers.PullRequest{
			PeerNodeID: r.PeerNodeID, SourceGrantID: r.SourceGrantID,
			DestinationGrantID: r.DestinationGrantID, DestinationPath: r.DestinationPath,
			ConflictPolicy: r.ConflictPolicy, VerifyChecksum: r.VerifyChecksum,
			BandwidthLimit: r.BandwidthLimit, MaxParallelFiles: r.MaxParallelFiles,
			MaxParallelChunks: r.MaxParallelChunks, CorrelationID: correlationID,
		},
		SourcePaths: r.SourcePaths, SourceNames: r.SourceNames, Operation: r.Operation,
		SubjectType: r.SubjectType, MovePlanID: r.MovePlanID, MovePlanToken: r.MovePlanToken,
	}
}

func (s *Server) createPullTransfer(w http.ResponseWriter, r *http.Request) {
	var request pullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, repeated, err := s.transfers.CreatePull(r.Context(), transfers.PullRequest{
		PeerNodeID: request.PeerNodeID, SourceGrantID: request.SourceGrantID,
		SourcePath: request.SourcePath, DestinationGrantID: request.DestinationGrantID,
		DestinationPath: request.DestinationPath, ConflictPolicy: request.ConflictPolicy,
		VerifyChecksum: request.VerifyChecksum, CorrelationID: r.Header.Get("X-Correlation-ID"),
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks,
	}, r.Header.Get("Idempotency-Key"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if repeated {
		status = http.StatusOK
	}
	writeJSON(w, status, job)
}

func (s *Server) planDirectoryPullTransfer(w http.ResponseWriter, r *http.Request) {
	var request pullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	plan, err := s.transfers.PlanDirectoryPull(r.Context(), transfers.PullRequest{
		PeerNodeID: request.PeerNodeID, SourceGrantID: request.SourceGrantID,
		SourcePath: request.SourcePath, DestinationGrantID: request.DestinationGrantID,
		DestinationPath: request.DestinationPath, ConflictPolicy: request.ConflictPolicy,
		VerifyChecksum: request.VerifyChecksum, CorrelationID: r.Header.Get("X-Correlation-ID"),
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	const previewLimit = 500
	if len(plan.Items) > previewLimit {
		plan.Items, plan.Truncated = plan.Items[:previewLimit], true
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) createDirectoryPullTransfer(w http.ResponseWriter, r *http.Request) {
	var request pullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, repeated, err := s.transfers.CreateDirectoryPull(r.Context(), transfers.PullRequest{
		PeerNodeID: request.PeerNodeID, SourceGrantID: request.SourceGrantID,
		SourcePath: request.SourcePath, DestinationGrantID: request.DestinationGrantID,
		DestinationPath: request.DestinationPath, ConflictPolicy: request.ConflictPolicy,
		VerifyChecksum: request.VerifyChecksum, CorrelationID: r.Header.Get("X-Correlation-ID"),
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks,
	}, r.Header.Get("Idempotency-Key"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if repeated {
		status = http.StatusOK
	}
	writeJSON(w, status, job)
}

func (s *Server) planBatchPullTransfer(w http.ResponseWriter, r *http.Request) {
	var request batchPullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	plan, err := s.transfers.PlanBatchPull(r.Context(), request.transferRequest(r.Header.Get("X-Correlation-ID")))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	const previewLimit = 500
	if len(plan.Items) > previewLimit {
		plan.Items, plan.Truncated = plan.Items[:previewLimit], true
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) createBatchPullTransfer(w http.ResponseWriter, r *http.Request) {
	var request batchPullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	requestHash := strings.TrimSpace(r.Header.Get("X-Jolt-Idempotency-Hash"))
	if requestHash == "" {
		encoded, _ := json.Marshal(request)
		sum := sha256.Sum256(encoded)
		requestHash = hex.EncodeToString(sum[:])
	}
	job, repeated, err := s.transfers.CreateBatchPull(r.Context(), request.transferRequest(r.Header.Get("X-Correlation-ID")), r.Header.Get("Idempotency-Key"), requestHash)
	if err != nil {
		if errors.Is(err, contracts.ErrIdempotencyConflict) {
			writeError(w, r, http.StatusConflict, "idempotency_conflict", "The Idempotency-Key was already used for a different request.", nil)
			return
		}
		s.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if repeated {
		status = http.StatusOK
	}
	writeJSON(w, status, job)
}

type prepareMTLSRotationRequest struct {
	ValidityDays int `json:"validity_days"`
}

func (s *Server) prepareMTLSRotation(w http.ResponseWriter, r *http.Request) {
	var request prepareMTLSRotationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.ValidityDays == 0 {
		request.ValidityDays = 365
	}
	certificate, err := s.certificates.PrepareRotation(time.Duration(request.ValidityDays)*24*time.Hour, r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, certificate)
}

type promoteMTLSRotationRequest struct {
	GraceHours *int `json:"grace_hours"`
}

func (s *Server) promoteMTLSRotation(w http.ResponseWriter, r *http.Request) {
	var request promoteMTLSRotationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	graceHours := 24
	if request.GraceHours != nil {
		graceHours = *request.GraceHours
	}
	certificate, err := s.certificates.Promote(time.Duration(graceHours)*time.Hour, r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificate)
}

func (s *Server) rollbackMTLSRotation(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.certificates.Rollback(r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certificate)
}

type revokeMTLSCertificateRequest struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

func (s *Server) revokeMTLSCertificate(w http.ResponseWriter, r *http.Request) {
	var request revokeMTLSCertificateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := s.certificates.Revoke(request.Serial, request.Reason, r.Header.Get("X-Correlation-ID")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) browseFilesystem(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	home, path, parent, items, err := s.files.BrowsePath(r.Context(), r.URL.Query().Get("path"), limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"home": home, "path": path, "parent": parent, "items": items,
	})
}

func (s *Server) listMounts(w http.ResponseWriter, r *http.Request) {
	mounts, err := s.files.ListMounts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": mounts})
}

func (s *Server) getMount(w http.ResponseWriter, r *http.Request) {
	mount, err := s.files.GetMount(r.Context(), r.PathValue("mountID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, mount)
}

type mountRequest struct {
	Name      string `json:"name"`
	LocalPath string `json:"local_path"`
	Mode      string `json:"mode"`
	Published *bool  `json:"published"`
	Enabled   *bool  `json:"enabled"`
}

func (s *Server) createMount(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusConflict, "configuration_managed_by_file", "Gerenciado por arquivo. Edite node.yaml e reinicie o node.", nil)
}

func (s *Server) updateMount(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusConflict, "configuration_managed_by_file", "Gerenciado por arquivo. Edite node.yaml e reinicie o node.", nil)
}

func (s *Server) deleteMount(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusConflict, "configuration_managed_by_file", "Gerenciado por arquivo. Edite node.yaml e reinicie o node.", nil)
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	page, err := s.files.ListPageFiltered(r.Context(), r.PathValue("mountID"), r.URL.Query().Get("path"), limit, r.URL.Query().Get("after"), signedAccessFilter(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": page.Items, "path": r.URL.Query().Get("path"), "has_more": page.HasMore, "next_after": page.NextAfter})
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	filter := signedAccessFilter(r)
	if r.Header.Get("X-Jolt-Internal-Canary") == "1" && s.files.IsCanary(r.Context(), r.PathValue("mountID"), r.URL.Query().Get("path")) {
		w.Header().Set("X-Jolt-Canary", "1")
	}
	item, err := s.files.MetadataFiltered(r.Context(), r.PathValue("mountID"), r.URL.Query().Get("path"), filter)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	scanSecrets := r.Header.Get("X-Jolt-Scan") == "secrets"
	if scanSecrets {
		w.Header().Set("X-Jolt-Scan-Applied", "secrets")
	}
	filter := signedAccessFilter(r)
	if r.Header.Get("X-Jolt-Internal-Canary") == "1" && s.files.IsCanary(r.Context(), r.PathValue("mountID"), r.URL.Query().Get("path")) {
		w.Header().Set("X-Jolt-Canary", "1")
	}
	file, info, err := s.files.OpenFiltered(r.Context(), r.PathValue("mountID"), r.URL.Query().Get("path"), filter)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer file.Close()
	if scanSecrets {
		if err := filesystem.ScanSecretPrefix(file); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if boolQuery(r, "editor") && info.Size() > editorMaxBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "editor_content_too_large",
			"O editor aceita arquivos de até 512 KB.", nil)
		return
	}
	w.Header().Set("Content-Disposition", contentDisposition("attachment", info.Name()))
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// contentDisposition builds a header that survives non-ASCII names. The quoted
// filename stays as an ASCII fallback for old clients, and the RFC 5987
// filename* parameter carries the real UTF-8 name, so "Relatório 2024.pdf"
// downloads under its own name instead of a mangled one.
func contentDisposition(disposition, name string) string {
	name = strings.Map(func(r rune) rune {
		// Control characters, quotes and path separators would break parsing or
		// let a crafted name redirect where the client writes the file.
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == '/' {
			return -1
		}
		return r
	}, name)
	if name == "" {
		name = "download"
	}
	ascii := make([]rune, 0, len(name))
	for _, r := range name {
		if r > 0x7f {
			ascii = append(ascii, '_')
			continue
		}
		ascii = append(ascii, r)
	}
	return fmt.Sprintf("%s; filename=%q; filename*=UTF-8''%s",
		disposition, string(ascii), encodeRFC5987(name))
}

// encodeRFC5987 percent-encodes everything outside the attr-char set defined by
// RFC 5987, which is stricter than url.QueryEscape: a space must become %20 and
// never '+', or the client stores the literal plus sign.
func encodeRFC5987(value string) string {
	const unreserved = "!#$&+-.^_`|~"
	var builder strings.Builder
	for _, b := range []byte(value) {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9',
			strings.IndexByte(unreserved, b) >= 0:
			builder.WriteByte(b)
		default:
			fmt.Fprintf(&builder, "%%%02X", b)
		}
	}
	return builder.String()
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	filter := signedAccessFilter(r)
	idempotency := signedSimpleUploadIdempotency(r)
	if filter != nil {
		candidate := entities.UploadSession{ID: "simple", MountID: r.PathValue("mountID"), Destination: path, Overwrite: boolQuery(r, "overwrite")}
		if idempotency != "" && s.store != nil {
			if err := s.files.ValidateUploadReauthorizationFiltered(r.Context(), candidate, filter); err != nil {
				s.fail(w, r, err)
				return
			}
			job, _, found, err := s.store.FindJobByIdempotency(r.Context(), idempotency)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if found {
				writeJSON(w, http.StatusOK, job)
				return
			}
		}
		if err := s.files.ValidateUploadDestinationFiltered(r.Context(), candidate, filter); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if boolQuery(r, "editor") {
		if r.ContentLength > editorMaxBytes {
			writeError(w, r, http.StatusRequestEntityTooLarge, "editor_content_too_large",
				"O editor aceita arquivos de até 512 KB.", nil)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, editorMaxBytes)
	}
	bandwidthLimit := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("bandwidth_limit_bytes_per_second")); raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil {
			bandwidthLimit = -1
		} else {
			bandwidthLimit = parsed
		}
	}
	job, repeated, err := s.jobs.CreateInline(r.Context(), jobs.CreateRequest{
		Type: "upload", MountID: r.PathValue("mountID"), Destination: path,
		CorrelationID: r.Header.Get("X-Correlation-ID"), Overwrite: boolQuery(r, "overwrite"),
		BandwidthLimit: bandwidthLimit,
	}, idempotency)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repeated {
		writeJSON(w, http.StatusOK, job)
		return
	}
	defer s.jobs.ReleaseBandwidthLimiter(job.ID)
	var bytes int64
	var operationErr error
	if filter != nil {
		bytes, operationErr = s.files.UploadFiltered(r.Context(), r.PathValue("mountID"), path, r.Body,
			boolQuery(r, "overwrite"), filter, s.jobs.BandwidthLimiter(job))
	} else {
		bytes, operationErr = s.files.Upload(r.Context(), r.PathValue("mountID"), path, r.Body,
			boolQuery(r, "overwrite"), s.jobs.BandwidthLimiter(job))
	}
	_ = s.jobs.Complete(r.Context(), &job, bytes, operationErr)
	if operationErr != nil {
		s.fail(w, r, operationErr)
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

type pathRequest struct {
	Path               string `json:"path"`
	SourcePath         string `json:"source_path"`
	DestinationPath    string `json:"destination_path"`
	Overwrite          bool   `json:"overwrite"`
	ConflictPolicy     string `json:"conflict_policy"`
	SourceChangePolicy string `json:"source_change_policy"`
	VerifyChecksum     bool   `json:"verify_checksum"`
	BandwidthLimit     int64  `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int    `json:"max_parallel_files"`
	MaxParallelChunks  int    `json:"max_parallel_chunks"`
}

func (s *Server) mkdir(w http.ResponseWriter, r *http.Request) {
	var request pathRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, repeated, err := s.jobs.Create(r.Context(), jobs.CreateRequest{
		Type: "mkdir", MountID: r.PathValue("mountID"), Destination: request.Path,
		CorrelationID: r.Header.Get("X-Correlation-ID"),
	}, idempotencyKey(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repeated {
		writeJSON(w, http.StatusOK, job)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) copy(w http.ResponseWriter, r *http.Request) {
	var request pathRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, repeated, err := s.jobs.Create(r.Context(), jobs.CreateRequest{
		Type: "copy_local", MountID: r.PathValue("mountID"), SourcePath: request.SourcePath,
		Destination: request.DestinationPath, CorrelationID: r.Header.Get("X-Correlation-ID"),
		Overwrite: request.Overwrite, ConflictPolicy: request.ConflictPolicy,
		SourceChangePolicy: request.SourceChangePolicy, VerifyChecksum: request.VerifyChecksum,
		BandwidthLimit:    request.BandwidthLimit,
		MaxParallelFiles:  request.MaxParallelFiles,
		MaxParallelChunks: request.MaxParallelChunks,
	}, idempotencyKey(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repeated {
		writeJSON(w, http.StatusOK, job)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) planCopy(w http.ResponseWriter, r *http.Request) {
	var request pathRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	policy := request.ConflictPolicy
	if policy == "" && request.Overwrite {
		policy = "overwrite"
	}
	plan, err := s.jobs.PlanCopy(r.Context(), r.PathValue("mountID"), request.SourcePath, request.DestinationPath, policy, request.VerifyChecksum)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	const previewLimit = 500
	if len(plan.Items) > previewLimit {
		plan.Items, plan.Truncated = plan.Items[:previewLimit], true
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) move(w http.ResponseWriter, r *http.Request) {
	var request pathRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, repeated, err := s.jobs.Create(r.Context(), jobs.CreateRequest{
		Type: "move_local", MountID: r.PathValue("mountID"), SourcePath: request.SourcePath,
		Destination: request.DestinationPath, CorrelationID: r.Header.Get("X-Correlation-ID"),
		Overwrite: request.Overwrite,
	}, idempotencyKey(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repeated {
		writeJSON(w, http.StatusOK, job)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	job, repeated, err := s.jobs.Create(r.Context(), jobs.CreateRequest{
		Type: "delete", MountID: r.PathValue("mountID"), SourcePath: path,
		CorrelationID: r.Header.Get("X-Correlation-ID"), Recursive: boolQuery(r, "recursive"),
	}, idempotencyKey(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repeated {
		writeJSON(w, http.StatusOK, job)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.jobs.List(r.Context(), limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	visible := items[:0]
	for _, item := range items {
		if s.hideJob(r.Context(), &item) {
			continue
		}
		visible = append(visible, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.jobs.Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.hideJob(r.Context(), &job) {
		s.fail(w, r, jobs.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// hideJob prevents historical job metadata from undoing a newly configured
// hidden-name rule. Errors may embed filenames, so omit them on protected mounts.
func (s *Server) hideJob(ctx context.Context, job *entities.Job) bool {
	if job.MountID == "" {
		return false
	}
	mount, err := s.files.GetMount(ctx, job.MountID)
	if errors.Is(err, filesystem.ErrNotFound) {
		return false
	}
	if err != nil {
		return true
	}
	if len(mount.HiddenPatterns) > 0 {
		job.Error = ""
	}
	for _, value := range []string{job.SourcePath, job.Destination} {
		if value == "" {
			continue
		}
		hidden, err := s.files.IsHiddenPath(ctx, job.MountID, value)
		if err != nil || hidden {
			return true
		}
	}
	return false
}

func (s *Server) jobSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.JobSummary(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) listJobItems(w http.ResponseWriter, r *http.Request) {
	job, err := s.jobs.Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.hideJob(r.Context(), &job) {
		s.fail(w, r, jobs.ErrNotFound)
		return
	}
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, next, err := s.store.ListJobItemsPage(r.Context(), r.PathValue("jobID"), after, limit)
	if err != nil {
		if errors.Is(err, contracts.ErrNotFound) {
			err = jobs.ErrNotFound
		}
		s.fail(w, r, err)
		return
	}
	mount, mountErr := s.files.GetMount(r.Context(), job.MountID)
	if mountErr != nil && !errors.Is(mountErr, filesystem.ErrNotFound) {
		s.fail(w, r, mountErr)
		return
	}
	visible := items[:0]
	for _, item := range items {
		if errors.Is(mountErr, filesystem.ErrNotFound) {
			visible = append(visible, item)
			continue
		}
		hide := false
		for _, value := range []string{item.RelativePath, item.SourcePath, item.DestinationPath} {
			if value == "" {
				continue
			}
			hidden, err := s.files.IsHiddenPath(r.Context(), job.MountID, value)
			if err != nil || hidden {
				hide = true
				break
			}
		}
		if !hide {
			if len(mount.HiddenPatterns) > 0 {
				item.Error = ""
			}
			visible = append(visible, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible, "next_after": next})
}

type overrideJobItemRequest struct {
	Action           string `json:"action"`
	ApplyToFollowing bool   `json:"apply_to_following"`
}

func (s *Server) overrideJobItem(w http.ResponseWriter, r *http.Request) {
	current, err := s.jobs.Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.hideJob(r.Context(), &current) {
		s.fail(w, r, jobs.ErrNotFound)
		return
	}
	ordinal, err := strconv.Atoi(r.PathValue("ordinal"))
	if err != nil || ordinal < 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_ordinal", "Item ordinal must be a non-negative integer.", nil)
		return
	}
	var request overrideJobItemRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, err := s.jobs.OverrideItem(r.Context(), r.PathValue("jobID"), ordinal, request.Action, request.ApplyToFollowing)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.hideJob(r.Context(), &job) {
		s.fail(w, r, jobs.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) streamJobEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "streaming_unavailable", "Event streaming is unavailable.", nil)
		return
	}
	after, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("after")), 10, 64)
	if lastEventID := strings.TrimSpace(r.Header.Get("Last-Event-ID")); lastEventID != "" {
		if parsed, err := strconv.ParseInt(lastEventID, 10, 64); err == nil && parsed > after {
			after = parsed
		}
	}
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	events, err := s.jobs.ListEvents(r.Context(), after, jobID, 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	poll := time.NewTicker(500 * time.Millisecond)
	heartbeat := time.NewTicker(15 * time.Second)
	defer poll.Stop()
	defer heartbeat.Stop()
	for {
		for _, event := range events {
			after = event.ID
			job, getErr := s.jobs.Get(r.Context(), event.JobID)
			if getErr != nil {
				continue
			}
			if s.hideJob(r.Context(), &job) {
				continue
			}
			if mount, err := s.files.GetMount(r.Context(), job.MountID); err == nil && len(mount.HiddenPatterns) > 0 {
				event.Message = ""
			}
			payload, marshalErr := json.Marshal(map[string]any{"event": event, "job": job})
			if marshalErr != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: job\ndata: %s\n\n", event.ID, payload); err != nil {
				return
			}
		}
		if len(events) > 0 {
			flusher.Flush()
			events, err = s.jobs.ListEvents(r.Context(), after, jobID, 100)
			if err != nil {
				return
			}
			if len(events) > 0 {
				continue
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-poll.C:
			events, err = s.jobs.ListEvents(r.Context(), after, jobID, 100)
			if err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) pauseJob(w http.ResponseWriter, r *http.Request) {
	s.controlJob(w, r, s.jobs.Pause)
}

func (s *Server) resumeJob(w http.ResponseWriter, r *http.Request) {
	s.controlJob(w, r, s.jobs.Resume)
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	s.controlJob(w, r, s.jobs.Cancel)
}

func (s *Server) retryJob(w http.ResponseWriter, r *http.Request) {
	s.controlJob(w, r, s.jobs.Retry)
}

func (s *Server) controlJob(w http.ResponseWriter, r *http.Request, action func(context.Context, string) (entities.Job, error)) {
	current, err := s.jobs.Get(r.Context(), r.PathValue("jobID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.hideJob(r.Context(), &current) {
		s.fail(w, r, jobs.ErrNotFound)
		return
	}
	job, err := action(r.Context(), r.PathValue("jobID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.hideJob(r.Context(), &job) {
		s.fail(w, r, jobs.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

type pairingInviteRequest struct {
	TargetNodeID  string `json:"target_node_id"`
	TransferMode  string `json:"transfer_mode"`
	IssuerRole    string `json:"issuer_role"`
	InviteeRole   string `json:"invitee_role"`
	Purpose       string `json:"purpose"`
	ClusterID     string `json:"cluster_id"`
	ExpiryMinutes int    `json:"expiry_minutes"`
}

func (s *Server) createPairingInvite(w http.ResponseWriter, r *http.Request) {
	var request pairingInviteRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	invite, token, err := s.pairing.CreateInvite(r.Context(), pairing.InviteInput{
		TargetNodeID: request.TargetNodeID, TransferMode: request.TransferMode,
		IssuerRole: request.IssuerRole, InviteeRole: request.InviteeRole,
		Purpose: request.Purpose, ClusterID: request.ClusterID, ExpiryMinutes: request.ExpiryMinutes,
		CorrelationID: r.Header.Get("X-Correlation-ID"),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite": invite, "invite_token": token})
}

func (s *Server) listPairingInvites(w http.ResponseWriter, r *http.Request) {
	items, err := s.pairing.ListInvites(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) revokePairingInvite(w http.ResponseWriter, r *http.Request) {
	if err := s.pairing.RevokeInvite(r.Context(), r.PathValue("inviteID")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type pairingRequestInput struct {
	InviteID            string    `json:"invite_id"`
	InviteToken         string    `json:"invite_token"`
	IssuerNodeID        string    `json:"issuer_node_id"`
	IssuerName          string    `json:"issuer_name"`
	IssuerFingerprint   string    `json:"issuer_fingerprint"`
	IssuerIdentityEpoch int       `json:"issuer_identity_epoch"`
	IssuerEndpoint      string    `json:"issuer_endpoint"`
	IssuerMTLSEndpoint  string    `json:"issuer_mtls_endpoint"`
	TransferMode        string    `json:"transfer_mode"`
	IssuerRole          string    `json:"issuer_role"`
	InviteeRole         string    `json:"invitee_role"`
	Purpose             string    `json:"purpose"`
	ClusterID           string    `json:"cluster_id"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func (s *Server) createPairingRequest(w http.ResponseWriter, r *http.Request) {
	var request pairingRequestInput
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := s.pairing.CreateIncomingRequest(r.Context(), pairing.IncomingRequestInput{
		InviteID: request.InviteID, InviteToken: request.InviteToken,
		IssuerNodeID: request.IssuerNodeID, IssuerName: request.IssuerName,
		IssuerFingerprint: request.IssuerFingerprint, IssuerIdentityEpoch: request.IssuerIdentityEpoch,
		IssuerEndpoint:     request.IssuerEndpoint,
		IssuerMTLSEndpoint: request.IssuerMTLSEndpoint,
		TransferMode:       request.TransferMode, IssuerRole: request.IssuerRole, InviteeRole: request.InviteeRole,
		Purpose: request.Purpose, ClusterID: request.ClusterID, ExpiresAt: request.ExpiresAt,
		CorrelationID: r.Header.Get("X-Correlation-ID"),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *Server) listPairingRequests(w http.ResponseWriter, r *http.Request) {
	items, err := s.pairing.ListRequests(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type approveInviteRequest struct {
	InviteToken       string `json:"invite_token"`
	PeerNodeID        string `json:"peer_node_id"`
	PeerName          string `json:"peer_name"`
	PeerFingerprint   string `json:"peer_fingerprint"`
	PeerIdentityEpoch int    `json:"peer_identity_epoch"`
	PeerEndpoint      string `json:"peer_endpoint"`
	PeerMTLSEndpoint  string `json:"peer_mtls_endpoint"`
}

func (s *Server) approvePairingInvite(w http.ResponseWriter, r *http.Request) {
	var request approveInviteRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	peer, err := s.pairing.ApproveInvite(r.Context(), r.PathValue("inviteID"), pairing.ApproveInviteInput{
		InviteToken: request.InviteToken, PeerNodeID: request.PeerNodeID,
		PeerName: request.PeerName, PeerFingerprint: request.PeerFingerprint,
		PeerIdentityEpoch: request.PeerIdentityEpoch,
		PeerEndpoint:      request.PeerEndpoint, PeerMTLSEndpoint: request.PeerMTLSEndpoint,
		CorrelationID: r.Header.Get("X-Correlation-ID"),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

type acceptRequestInput struct {
	ConfirmedFingerprint string `json:"confirmed_fingerprint"`
}

func (s *Server) acceptPairingRequest(w http.ResponseWriter, r *http.Request) {
	var request acceptRequestInput
	if !decodeJSON(w, r, &request) {
		return
	}
	peer, err := s.pairing.AcceptRequest(r.Context(), r.PathValue("requestID"), request.ConfirmedFingerprint, r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

func (s *Server) rejectPairingRequest(w http.ResponseWriter, r *http.Request) {
	if err := s.pairing.RejectRequest(r.Context(), r.PathValue("requestID")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPeers(w http.ResponseWriter, r *http.Request) {
	items, err := s.pairing.ListPeers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) revokePeer(w http.ResponseWriter, r *http.Request) {
	peerNodeID := strings.TrimSpace(r.PathValue("peerNodeID"))
	if err := s.pairing.RevokePeer(r.Context(), peerNodeID, r.Header.Get("X-Correlation-ID")); err != nil {
		s.fail(w, r, err)
		return
	}
	canceled, err := s.jobs.CancelPeer(r.Context(), peerNodeID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"peer_node_id": peerNodeID, "state": "revoked", "canceled_jobs": canceled,
	})
}

type updatePeerEndpointsRequest struct {
	Endpoint     string `json:"endpoint"`
	MTLSEndpoint string `json:"mtls_endpoint"`
}

func (s *Server) updatePeerEndpoints(w http.ResponseWriter, r *http.Request) {
	var request updatePeerEndpointsRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	peer, err := s.pairing.UpdatePeerEndpoints(r.Context(), r.PathValue("peerNodeID"), pairing.UpdatePeerEndpointsInput{
		Endpoint: request.Endpoint, MTLSEndpoint: request.MTLSEndpoint,
		CorrelationID: r.Header.Get("X-Correlation-ID"),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

type recoverPeerIdentityRequest struct {
	ConfirmedFingerprint string `json:"confirmed_fingerprint"`
}

func (s *Server) recoverPeerIdentity(w http.ResponseWriter, r *http.Request) {
	var request recoverPeerIdentityRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	peer, err := s.pairing.RecoverPeerIdentity(r.Context(), r.PathValue("peerNodeID"),
		request.ConfirmedFingerprint, r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

func (s *Server) applyPeerIdentityHandover(w http.ResponseWriter, r *http.Request) {
	var handover joltcrypto.IdentityHandover
	if !decodeJSON(w, r, &handover) {
		return
	}
	if handover.NodeID != r.PathValue("peerNodeID") {
		writeError(w, r, http.StatusBadRequest, "handover_peer_mismatch",
			"The handover node_id does not match the selected peer.", nil)
		return
	}
	peer, err := s.pairing.ApplyIdentityHandover(r.Context(), handover, r.Header.Get("X-Correlation-ID"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, peer)
}

type grantRequest struct {
	PeerNodeID       string                    `json:"peer_node_id"`
	MountID          string                    `json:"mount_id"`
	Path             string                    `json:"path"`
	Direction        string                    `json:"direction"`
	Permissions      entities.GrantPermissions `json:"permissions"`
	ConflictPolicies []string                  `json:"conflict_policies"`
	VisibleToPeer    bool                      `json:"visible_to_peer"`
	Enabled          *bool                     `json:"enabled"`
}

func (s *Server) grantInput(r *http.Request, request grantRequest) grants.Input {
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	return grants.Input{
		PeerNodeID: request.PeerNodeID, MountID: request.MountID, Path: request.Path,
		Direction: request.Direction, Permissions: request.Permissions,
		ConflictPolicies: request.ConflictPolicies, VisibleToPeer: request.VisibleToPeer,
		Enabled: enabled, CorrelationID: r.Header.Get("X-Correlation-ID"),
	}
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	items, err := s.grants.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusConflict, "configuration_managed_by_file", "Gerenciado por arquivo. Edite node.yaml e reinicie o node.", nil)
}

func (s *Server) updateGrant(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusConflict, "configuration_managed_by_file", "Gerenciado por arquivo. Edite node.yaml e reinicie o node.", nil)
}

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusConflict, "configuration_managed_by_file", "Gerenciado por arquivo. Edite node.yaml e reinicie o node.", nil)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code := http.StatusInternalServerError, "internal_error"
	var maxBytesError *http.MaxBytesError
	var secretError *filesystem.SecretError
	switch {
	case errors.As(err, &secretError):
		status, code = http.StatusForbidden, "secret_detected"
		if r.Header.Get("X-Jolt-Scan") == "secrets" {
			w.Header().Set("X-Jolt-Secret-Kind", secretError.Kind)
		}
	case errors.As(err, &maxBytesError):
		status, code = http.StatusRequestEntityTooLarge, "editor_content_too_large"
	case errors.Is(err, filesystem.ErrUploadTooLarge):
		status, code = http.StatusRequestEntityTooLarge, "upload_too_large"
	case errors.Is(err, filesystem.ErrUploadContentRejected):
		status, code = http.StatusUnprocessableEntity, "upload_content_rejected"
	case errors.Is(err, filesystem.ErrInsufficientSpace):
		status, code = http.StatusInsufficientStorage, "insufficient_storage"
	case errors.Is(err, filesystem.ErrFilteredHidden):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, filesystem.ErrFilteredBlocked):
		status, code = http.StatusForbidden, "file_type_not_allowed"
	case errors.Is(err, filesystem.ErrTrashNotFound):
		status, code = http.StatusNotFound, "trash_not_found"
	case errors.Is(err, filesystem.ErrTrashUnavailable):
		status, code = http.StatusConflict, "trash_unavailable"
	case errors.Is(err, filesystem.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, filesystem.ErrHiddenName):
		status, code = http.StatusUnprocessableEntity, "hidden_name"
	case errors.Is(err, filesystem.ErrProtectedTree):
		status, code = http.StatusConflict, "protected_tree"
	case errors.Is(err, filesystem.ErrReadOnly):
		status, code = http.StatusForbidden, "mount_read_only"
	case errors.Is(err, filesystem.ErrTraversal):
		status, code = http.StatusBadRequest, "path_traversal"
	case errors.Is(err, filesystem.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, filesystem.ErrSourceChanged):
		status, code = http.StatusConflict, "upload_destination_changed"
	case errors.Is(err, filesystem.ErrDisabled):
		status, code = http.StatusConflict, "mount_disabled"
	case errors.Is(err, filesystem.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, pairing.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_pairing_request"
	case errors.Is(err, pairing.ErrNotFound):
		status, code = http.StatusNotFound, "pairing_not_found"
	case errors.Is(err, pairing.ErrExpired):
		status, code = http.StatusGone, "pairing_expired"
	case errors.Is(err, pairing.ErrFingerprintMismatch):
		status, code = http.StatusConflict, "fingerprint_mismatch"
	case errors.Is(err, jobs.ErrNotFound):
		status, code = http.StatusNotFound, "job_not_found"
	case errors.Is(err, jobs.ErrInvalidState):
		status, code = http.StatusConflict, "invalid_job_state"
	case errors.Is(err, jobs.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_job_request"
	case errors.Is(err, transfers.ErrMoveIncomplete):
		status, code = http.StatusConflict, "move_incomplete"
	case errors.Is(err, jobs.ErrTreeChanged):
		status, code = http.StatusConflict, "tree_changed"
	case errors.Is(err, jobs.ErrPlanRejected):
		status, code = http.StatusForbidden, "plan_rejected"
	case errors.Is(err, contracts.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, jobs.ErrWaitingPeer):
		status, code = http.StatusConflict, "peer_unavailable"
	case errors.Is(err, grants.ErrNotFound):
		status, code = http.StatusNotFound, "grant_not_found"
	case errors.Is(err, grants.ErrConflict):
		status, code = http.StatusConflict, "grant_conflict"
	case errors.Is(err, grants.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_grant"
	case errors.Is(err, joltcrypto.ErrRotationPending), errors.Is(err, joltcrypto.ErrNoRotationPending),
		errors.Is(err, joltcrypto.ErrRollbackUnavailable):
		status, code = http.StatusConflict, "mtls_rotation_conflict"
	case errors.Is(err, joltcrypto.ErrCertificateInvalid):
		status, code = http.StatusBadRequest, "invalid_mtls_certificate"
	case errors.Is(err, joltcrypto.ErrCertificateRevoked):
		status, code = http.StatusConflict, "mtls_certificate_revoked"
	case errors.Is(err, joltcrypto.ErrIdentityConfirmation):
		status, code = http.StatusConflict, "identity_confirmation_mismatch"
	case errors.Is(err, joltcrypto.ErrIdentityRestart):
		status, code = http.StatusConflict, "identity_restart_required"
	case errors.Is(err, transfers.ErrForbidden):
		status, code = http.StatusForbidden, "transfer_forbidden"
	case errors.Is(err, transfers.ErrPeerUpgradeRequired):
		status, code = http.StatusConflict, "peer_upgrade_required"
	case errors.Is(err, transfers.ErrPeer):
		status, code = http.StatusConflict, "peer_unavailable"
	case errors.Is(err, transfers.ErrInvalid):
		status, code = http.StatusBadRequest, "invalid_transfer"
	}
	if status == http.StatusInternalServerError {
		s.log.Error("request failed", "error", err, "correlation_id", r.Header.Get("X-Correlation-ID"))
	}
	if errors.Is(err, filesystem.ErrFilteredHidden) {
		writeError(w, r, status, code, filesystem.ErrNotFound.Error(), nil)
		return
	}
	if errors.Is(err, filesystem.ErrUploadContentRejected) {
		writeError(w, r, status, code, "O conteúdo enviado foi recusado pela inspeção.", nil)
		return
	}
	writeError(w, r, status, code, err.Error(), nil)
}

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = io.WriteString(w, openAPISpec)
}

func (s *Server) swagger(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, swaggerHTML)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "The request body is not valid JSON.", map[string]any{"cause": err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details, "correlation_id": r.Header.Get("X-Correlation-ID")}})
}

func secureEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func boolQuery(r *http.Request, key string) bool {
	value, _ := strconv.ParseBool(r.URL.Query().Get(key))
	return value
}

func idempotencyKey(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		return ""
	}
	return r.Method + ":" + r.URL.Path + ":" + key
}

func randomID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

const swaggerHTML = `<!doctype html><html><head><title>jolt node API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="swagger-ui"></div><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({url:'/openapi.yaml',dom_id:'#swagger-ui',persistAuthorization:true})</script></body></html>`

const openAPISpec = `openapi: 3.1.0
info:
  title: jolt node API
  version: 0.1.0
  description: >
    Mount hidden_patterns are enforced for all callers. Direct reads of hidden
    paths return 404, attempts to create a hidden name return 422 hidden_name,
    and destructive jobs involving protected trees fail with protected_tree.
servers:
  - url: /
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  schemas:
    SignedLocalCopyRequest:
      type: object
      additionalProperties: false
      required: [mount_id, source_path, destination_path]
      properties:
        mount_id: {type: string}
        source_path: {type: string}
        destination_path: {type: string}
        overwrite: {type: boolean}
        recursive: {type: boolean}
        conflict_policy: {type: string}
        source_change_policy: {type: string}
        verify_checksum: {type: boolean}
        bandwidth_limit_bytes_per_second: {type: integer, format: int64, minimum: 0}
        max_parallel_files: {type: integer, minimum: 0, maximum: 32}
        max_parallel_chunks: {type: integer, minimum: 0, maximum: 16}
        max_attempts: {type: integer}
    FileConfiguration:
      type: object
      readOnly: true
      required: [source, apply_mode, mounts_mutable, grants_mutable]
      properties:
        source: {type: string, enum: [yaml]}
        apply_mode: {type: string, enum: [restart]}
        mounts_mutable: {type: boolean, const: false}
        grants_mutable: {type: boolean, const: false}
        revision: {type: string, description: Applied public configuration digest}
    GrantStatus:
      type: object
      readOnly: true
      required: [enabled, configured_enabled]
      properties:
        enabled: {type: boolean, description: Effective authorization after trust and filesystem validation}
        configured_enabled: {type: boolean, description: Operator value in node.yaml}
        inactive_reason:
          type: string
          enum: [disabled, revoked, peer_untrusted, mount_unavailable, mount_read_only, peer_role_incompatible, path_unavailable]
    GrantPermissions:
      type: object
      required: [read, write, delete, rename]
      properties:
        read: {type: boolean}
        write: {type: boolean}
        delete: {type: boolean}
        rename: {type: boolean}
    Grant:
      allOf:
        - $ref: '#/components/schemas/GrantStatus'
        - type: object
          required: [grant_id, peer_node_id, mount_id, path, direction, permissions, conflict_policies, visible_to_peer, correlation_id, created_at, updated_at]
          properties:
            grant_id: {type: string}
            peer_node_id: {type: string}
            mount_id: {type: string}
            path: {type: string, description: Relative path inside the mount}
            direction: {type: string, enum: [send, receive, send_receive]}
            permissions: {$ref: '#/components/schemas/GrantPermissions'}
            conflict_policies:
              type: [array, 'null']
              items: {type: string}
            exclude:
              type: array
              maxItems: 64
              items: {type: string}
              description: Basename globs excluded from source and destination paths; moves that include excluded content are refused.
            visible_to_peer: {type: boolean}
            correlation_id: {type: string}
            created_at: {type: string, format: date-time}
            updated_at: {type: string, format: date-time}
    Error:
      type: object
      properties:
        error:
          type: object
          properties:
            code: {type: string}
            message: {type: string}
            correlation_id: {type: string}
security:
  - bearerAuth: []
paths:
  /health:
    get:
      security: []
      responses:
        "200": {description: Healthy}
  /api/v1/node:
    get:
      responses:
        "200":
          description: Node identity and capabilities
          content:
            application/json:
              schema:
                type: object
                properties:
                  configuration: {$ref: '#/components/schemas/FileConfiguration'}
  /api/v1/config/effective:
    get:
      responses:
        "200":
          description: Effective configuration; secrets and internal paths redacted
          content:
            application/json:
              schema:
                type: object
                properties:
                  configuration: {$ref: '#/components/schemas/FileConfiguration'}
  /api/v1/fs/browse:
    get:
      parameters:
        - in: query
          name: path
          schema: {type: string}
        - in: query
          name: limit
          schema: {type: integer}
      responses:
        "200": {description: Directory listing starting from the node's home directory, used to pick a mount's LocalPath}
  /api/v1/mounts:
    get:
      responses:
        "200": {description: Configured mounts}
    post:
      parameters:
        - in: header
          name: Idempotency-Key
          schema: {type: string}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name, local_path, mode]
              properties:
                name: {type: string}
                local_path: {type: string, description: Administrative input; never returned}
                mode: {type: string, enum: [read_only, read_write]}
                published: {type: boolean}
                enabled: {type: boolean}
      responses:
        "409": {description: configuration_managed_by_file - edit node.yaml and restart}
  /api/v1/mounts/{mountID}:
    parameters:
      - {in: path, name: mountID, required: true, schema: {type: string}}
    get:
      responses:
        "200": {description: Configured mount and observed filesystem availability}
    put:
      responses:
        "409": {description: configuration_managed_by_file - edit node.yaml and restart}
    delete:
      responses:
        "409": {description: configuration_managed_by_file - edit node.yaml and restart}
  /api/v1/mounts/{mountID}/files:
    get:
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact local listing; supported when signed_local_read_v1 is advertised}
        - {in: query, name: path, schema: {type: string}}
        - {in: query, name: limit, schema: {type: integer, maximum: 1000}}
        - {in: query, name: after, schema: {type: string}, description: Opaque keyset cursor from next_after}
      responses:
        "200":
          description: Directory entries in deterministic order; follow next_after while has_more is true
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
          content:
            application/json:
              schema:
                type: object
                properties:
                  items: {type: array, items: {type: object}}
                  has_more: {type: boolean}
                  next_after: {type: string}
        "403": {description: Invalid or expired signed context, or visible blocked entry}
        "404": {description: Hidden entry or path not found}
        "503": {description: Signed request deadline enforcement unavailable}
    delete:
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: recursive, schema: {type: boolean}}
      responses:
        "202": {description: Persistent job queued for asynchronous execution}
  /api/v1/mounts/{mountID}/files/content:
    get:
      description: X-Jolt-Scan secrets scans the first 64 KiB before serving, including Range requests, and confirms enforcement in X-Jolt-Scan-Applied.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: editor, schema: {type: boolean}, description: Enables the 512 KB text-editor limit}
        - {in: header, name: X-Jolt-Scan, schema: {type: string, enum: [secrets]}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact local content read}
      responses:
        "200":
          description: File stream
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "206":
          description: Partial file stream
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: secret_detected, file_type_not_allowed, or invalid_signed_context}
        "404": {description: Hidden entry or path not found}
        "503": {description: Signed request deadline enforcement unavailable}
    put:
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: overwrite, schema: {type: boolean}}
        - {in: query, name: editor, schema: {type: boolean}, description: Enables the 512 KB text-editor limit}
        - {in: query, name: bandwidth_limit_bytes_per_second, schema: {type: integer, format: int64, minimum: 0}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context binding the exact query and idempotency key}
        - {in: header, name: Idempotency-Key, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/octet-stream:
            schema: {type: string, format: binary}
      responses:
        "200": {description: Previously completed idempotent upload job}
        "201":
          description: Completed upload job
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: Invalid signed context or destination denied}
        "404": {description: Hidden destination or parent not found}
        "422": {description: hidden_name or upload_content_rejected by the configured upload inspection}
  /api/v1/mounts/{mountID}/files/metadata:
    get:
      summary: Returns metadata for one entry
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact local metadata read}
      responses:
        "200":
          description: Entry name, type, size and modification time
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: file_type_not_allowed or invalid_signed_context}
        "404": {description: Entry not found}
        "503": {description: Signed request deadline enforcement unavailable}
  /api/v1/mounts/{mountID}/files/directories:
    post:
      summary: Creates a directory
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [path]
              properties:
                path: {type: string}
      responses:
        "200": {description: Completed mkdir job}
        "403": {description: The mount is read-only}
        "422": {description: hidden_name - the destination is hidden by mount configuration}
  /api/v1/mounts/{mountID}/trash:
    get:
      summary: Lists what the mount's trash keeps
      description: Present only for mounts with trash enabled in node.yaml. Deleting an entry on such a mount moves it here for the configured retention.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
      responses:
        "200": {description: The kept entries, newest first}
        "404": {description: Unknown mount}
  /api/v1/mounts/{mountID}/trash/{trashID}:
    get:
      summary: Reads one kept entry
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: trashID, required: true, schema: {type: string}}
      responses:
        "200": {description: The kept entry}
        "404": {description: trash_not_found}
    delete:
      summary: Purges a kept entry for good
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: trashID, required: true, schema: {type: string}}
      responses:
        "200": {description: The purged entry}
        "404": {description: trash_not_found}
  /api/v1/mounts/{mountID}/trash/{trashID}/restore:
    post:
      summary: Puts a kept entry back where it was
      description: Fails with conflict if the name is taken, and with not found if its parent folder is gone. Never overwrites.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: trashID, required: true, schema: {type: string}}
      responses:
        "200": {description: The restored entry}
        "403": {description: The mount is read-only}
        "404": {description: trash_not_found, or the original folder no longer exists}
        "409": {description: The original name is taken}
        "422": {description: hidden_name - the original name is now hidden by mount configuration}
  /api/v1/mounts/{mountID}/files/move:
    post:
      summary: Moves or renames an entry inside one mount
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [source_path, destination_path]
              properties:
                source_path: {type: string}
                destination_path: {type: string}
                overwrite: {type: boolean}
      responses:
        "200": {description: Completed move job}
        "409": {description: The destination exists and overwrite was not requested}
  /api/v1/mounts/{mountID}/files/destructive-plans:
    post:
      summary: Inspects a directory tree and records a five-minute destructive plan
      description: Requires the operational bearer token. The subject is the actor the Control Tower authenticated. The response carries the one-use confirmation token once; only its hash is stored. Available when the node runs signed jobs.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [subject_type, subject_id, operation, source_path]
              properties:
                subject_type: {type: string, enum: [user, service_account]}
                subject_id: {type: string}
                operation: {type: string, enum: [delete, move]}
                source_path: {type: string}
                destination_path: {type: string}
                overwrite: {type: boolean}
      responses:
        "201": {description: Plan with counts, expiry and confirmation token}
        "400": {description: Invalid request, a file instead of a directory, or a path outside the mount}
        "409": {description: Protected entries in the tree, or the move destination exists without overwrite}
        "503": {description: Destructive plans unavailable on this node}
  /api/v1/mounts/{mountID}/files/destructive-plans/{planID}/accept:
    post:
      summary: Confirms a destructive plan and creates its job
      description: Requires the operational bearer token, the plan token and an Idempotency-Key. The job waits for a signed authorization and revalidates the tree before changing anything.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: planID, required: true, schema: {type: string}}
        - {in: header, name: Idempotency-Key, required: true, schema: {type: string, maxLength: 256}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [subject_type, subject_id, token]
              properties:
                subject_type: {type: string, enum: [user, service_account]}
                subject_id: {type: string}
                token: {type: string}
      responses:
        "200": {description: The same job, for a repeated request}
        "202": {description: Job created, waiting for authorization}
        "403": {description: Unknown, expired or mismatched plan or token}
        "409": {description: The tree changed after the plan, or the key was reused}
        "503": {description: Destructive plans unavailable on this node}
  /api/v1/mounts/{mountID}/files/archive:
    get:
      summary: Streams a ZIP of a directory, or of the selected entries inside it
      description: >
        Symlinks are skipped and counted in X-Jolt-Archive-Skipped-Symlinks
        rather than followed. The size is measured before streaming begins, so
        an oversized selection is refused with a status code instead of
        producing a truncated download. X-Jolt-Scan secrets scans every file
        before the response and again as each entry is opened.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: name, schema: {type: array, items: {type: string}}, description: Direct children to include; omit for the whole directory}
        - {in: query, name: compress, schema: {type: boolean}, description: Deflate instead of Store; off by default because media is already compressed}
        - {in: header, name: X-Jolt-Scan, schema: {type: string, enum: [secrets]}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact local archive operation}
      responses:
        "200":
          description: ZIP stream
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "400": {description: Selection exceeds the configured entry or byte limit}
        "403": {description: secret_detected, file_type_not_allowed, or invalid_signed_context}
        "404": {description: Hidden entry or path not found}
        "503": {description: Signed request deadline enforcement unavailable}
  /api/v1/mounts/{mountID}/files/archive/plan:
    get:
      summary: Reports what an archive would contain without writing it
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: name, schema: {type: array, items: {type: string}}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact archive plan}
      responses:
        "200":
          description: File count, total bytes, skipped symlinks and the configured limits
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: file_type_not_allowed or invalid_signed_context}
        "404": {description: Hidden entry or path not found}
        "503": {description: Signed request deadline enforcement unavailable}
  /api/v1/mounts/{mountID}/files/search:
    get:
      summary: Searches a subtree by name and metadata
      description: >
        Bounded by SEARCH_MAX_RESULTS, SEARCH_MAX_ENTRIES and SEARCH_TIMEOUT.
        Symlinks are never followed. A partial result sets truncated with a
        truncated_reason of results, entries, depth or timeout. Requests with
        X-Jolt-Agent-Search set to 1 are additionally bounded to depth 16,
        10000 examined entries, 200 results and 10 seconds. The node confirms
        enforcement in the X-Jolt-Agent-Search-Applied response header.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: query, schema: {type: string}, description: Case-insensitive substring of the entry name}
        - {in: header, name: X-Jolt-Agent-Search, schema: {type: string, enum: ["1"]}, description: Apply the bounded agent search profile}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact search}
        - {in: query, name: type, schema: {type: string, enum: [file, directory]}}
        - {in: query, name: extensions, schema: {type: string}, description: Comma-separated extensions}
        - {in: query, name: min_size, schema: {type: integer, format: int64}}
        - {in: query, name: max_size, schema: {type: integer, format: int64}}
        - {in: query, name: modified_after, schema: {type: string, format: date-time}}
        - {in: query, name: modified_before, schema: {type: string, format: date-time}}
        - {in: query, name: limit, schema: {type: integer}}
      responses:
        "200":
          description: Matching entries plus scanned count and truncation state
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "400": {description: No query or filter was supplied}
        "403": {description: file_type_not_allowed or invalid_signed_context}
        "404": {description: Hidden entry or path not found}
        "503": {description: Signed request deadline enforcement unavailable}
  /api/v1/mounts/{mountID}/files/disk-usage:
    get:
      summary: Measures allocated disk usage recursively, largest entries first
      description: >
        Uses allocated blocks rather than apparent file size. Directory totals
        include their descendants, hard links are counted once and symlinks are
        never followed. Bounded by DISK_USAGE_MAX_ENTRIES and DISK_USAGE_TIMEOUT;
        partial scans set truncated or read_errors.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: query, name: path, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context for this exact disk usage scan}
      responses:
        "200":
          description: Total allocated bytes, direct children and scan completeness
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: file_type_not_allowed or invalid_signed_context}
        "404": {description: Hidden entry or path not found}
        "503": {description: Signed request deadline enforcement unavailable}
  /api/v1/mounts/{mountID}/files/uploads:
    get:
      summary: Lists unfinished resumable uploads for a mount
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
      responses:
        "200": {description: Upload sessions with their durable offsets}
    post:
      summary: Opens a resumable upload session
      description: >
        The declared size caps what the node will write and is verified before
        the file is published, so a truncated upload can never replace a good
        file. One destination may hold only one open session. An internal signed
        context binds the exact request body and creates a session bound to the
        authenticated actor and credential when signed_upload_sessions_v1 is advertised.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed upload admission context}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [path, size]
              properties:
                path: {type: string}
                size: {type: integer, format: int64}
                overwrite: {type: boolean}
                checksum: {type: string, description: Optional SHA-256 verified before publishing}
                chunk_size: {type: integer, format: int64}
      responses:
        "201":
          description: Created session
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: Signed context invalid or destination denied}
        "409": {description: Another unfinished upload already targets this destination}
        "413": {description: Declared size exceeds UPLOAD_MAX_BYTES}
        "422": {description: hidden_name - the destination is hidden by mount configuration}
        "429": {description: UPLOAD_MAX_SESSIONS reached; Retry-After carries retry guidance}
        "507": {description: Reservation budget or available disk safety margin exhausted}
  /api/v1/mounts/{mountID}/files/uploads/{uploadID}:
    get:
      summary: Reports the durable offset of a resumable upload
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: uploadID, required: true, schema: {type: string}}
      responses:
        "200": {description: Session with durable offset, state (open, publishing or completed), and completed_at/checksum for completed receipts}
        "410": {description: The session expired}
    patch:
      summary: Appends one chunk at the offset named by Content-Range
      description: >
        Each chunk is fsynced before the new offset is reported. A mismatch
        answers 409 with the authoritative offset in X-Jolt-Upload-Offset so the
        client seeks there instead of restarting.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: uploadID, required: true, schema: {type: string}}
        - {in: header, name: Content-Range, required: true, schema: {type: string}, description: "bytes <start>-<end>/<total>"}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context required for a bound session}
      requestBody:
        required: true
        content:
          application/octet-stream:
            schema: {type: string, format: binary}
      responses:
        "200":
          description: Session with the new offset
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: Signed context required or invalid, or destination denied}
        "409": {description: Offset mismatch; X-Jolt-Upload-Offset carries the stored offset}
        "413": {description: Chunk exceeds the session chunk_size or upload limit}
        "507": {description: Available disk safety margin exhausted}
    delete:
      summary: Aborts a resumable upload and removes its partial file
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: uploadID, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context required for a bound session}
      responses:
        "204":
          description: Upload discarded
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "403": {description: Signed context required or invalid, or destination denied}
  /api/v1/mounts/{mountID}/files/uploads/{uploadID}/verification:
    get:
      summary: SHA-256 verification of every received byte for safe source re-selection
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: uploadID, required: true, schema: {type: string}}
        - {in: query, name: after, schema: {type: integer, format: int64, minimum: 0}, description: Byte cursor returned by next_after}
      responses:
        "200":
          description: At most sixteen 8 MiB blocks; zero next_after means verification is complete
          content:
            application/json:
              schema:
                type: object
                required: [offset, blocks, next_after]
                properties:
                  offset: {type: integer, format: int64}
                  next_after: {type: integer, format: int64}
                  blocks:
                    type: array
                    items:
                      type: object
                      required: [offset, size, sha256]
                      properties:
                        offset: {type: integer, format: int64}
                        size: {type: integer, format: int64, maximum: 8388608}
                        sha256: {type: string}
        "409": {description: Upload already completed}
        "410": {description: Session expired}
  /api/v1/mounts/{mountID}/files/uploads/{uploadID}/complete:
    post:
      summary: Verifies and publishes a completed resumable upload
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: uploadID, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, schema: {type: string}, description: Internal signed context required for a bound session}
      responses:
        "201":
          description: Durable completion receipt including upload_id, destination_path, size, SHA-256 checksum, state and completed_at; repeat returns the same receipt until expiry
          headers:
            X-Jolt-Access-Applied: {description: Confirms enforcement when a signed context is supplied, schema: {type: string, enum: [v1]}}
        "400": {description: The upload is short of the declared size or its checksum does not match}
        "403": {description: Signed context required or invalid, or destination denied}
        "409": {description: The destination exists and the session does not allow overwrite}
        "422": {description: upload_content_rejected; the rejected partial and upload session are removed}
  /api/v1/mounts/{mountID}/files/uploads/{uploadID}/authorize:
    post:
      summary: Explicitly reauthorize a resumable upload session
      description: A signed context is required. It binds the current session identity and destination; a bound session can only be reauthorized for the same actor.
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: path, name: uploadID, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, required: true, schema: {type: string}}
      responses:
        "204":
          description: Session reauthorized
          headers:
            X-Jolt-Access-Applied: {description: Confirms signed context enforcement, schema: {type: string, enum: [v1]}}
        "403": {description: Invalid, stale or insufficient authorization}
        "404": {description: Session not found or hidden}
  /api/v1/mounts/{mountID}/files/copy/plan:
    post:
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [source_path, destination_path]
              properties:
                source_path: {type: string}
                destination_path: {type: string}
                conflict_policy: {type: string, enum: [skip, overwrite, rename, fail, ask, checksum]}
                verify_checksum: {type: boolean}
                bandwidth_limit_bytes_per_second: {type: integer, format: int64, minimum: 0}
                max_parallel_files: {type: integer, minimum: 1, maximum: 32}
                max_parallel_chunks: {type: integer, minimum: 1, maximum: 16}
      responses:
        "200": {description: Copy manifest and conflict preview, capped at 500 returned items}
  /api/v1/mounts/{mountID}/files/copy:
    post:
      parameters:
        - {in: path, name: mountID, required: true, schema: {type: string}}
        - {in: header, name: Idempotency-Key, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [source_path, destination_path]
              properties:
                source_path: {type: string}
                destination_path: {type: string}
                conflict_policy: {type: string, enum: [skip, overwrite, rename, fail, ask, checksum]}
                bandwidth_limit_bytes_per_second: {type: integer, format: int64, minimum: 0}
                max_parallel_files: {type: integer, minimum: 1, maximum: 32}
                max_parallel_chunks: {type: integer, minimum: 1, maximum: 16}
                source_change_policy: {type: string, enum: [fail, retry, copy_anyway], default: fail}
                verify_checksum: {type: boolean}
      responses:
        "202": {description: Durable itemized copy job queued}
  /api/v1/jobs:
    get:
      responses:
        "200": {description: Persistent job history}
  /api/v1/jobs/signed-local-copy/prepare:
    post:
      summary: Prepare immutable options for a signed local copy
      description: Requires the operational bearer token. Computes normalized options and their digest without creating a job or authorizing execution.
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/SignedLocalCopyRequest'}
      responses:
        "200": {description: Normalized options, digest and whether signed execution is enabled}
        "400": {description: Invalid request or noncanonical paths}
        "503": {description: Signed job creation unavailable}
  /api/v1/jobs/signed-local-copy:
    post:
      summary: Create a signed local copy awaiting validation
      description: Requires the operational bearer token and a job-bound signed envelope matching the normalized request. The job is queued once its first authorization is registered and runs only while that authorization is renewed.
      parameters:
        - {in: header, name: X-Jolt-Access-Authorization, required: true, schema: {type: string}}
        - {in: header, name: Idempotency-Key, required: true, schema: {type: string, maxLength: 128}}
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: '#/components/schemas/SignedLocalCopyRequest'}
      responses:
        "200": {description: Existing job returned for an identical request}
        "202": {description: Job created in waiting_validation awaiting its first authorization}
        "400": {description: Invalid body, scope, signature or idempotency key}
        "409": {description: Idempotency key or job identifier conflict}
        "503": {description: Signed job creation unavailable}
  /api/v1/jobs/summary:
    get:
      summary: Counts all durable jobs by state, independent of history pagination
      responses:
        "200":
          description: Current counts and observation time
          content:
            application/json:
              schema:
                type: object
                required: [counts, observed_at]
                properties:
                  counts: {type: object, additionalProperties: {type: integer}}
                  observed_at: {type: string, format: date-time}
  /api/v1/jobs/events:
    get:
      parameters:
        - {in: query, name: after, schema: {type: integer, format: int64}}
        - {in: query, name: job_id, schema: {type: string}}
      responses:
        "200":
          description: Resumable Server-Sent Events stream
          content:
            text/event-stream: {}
  /api/v1/jobs/{jobID}:
    get:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
      responses:
        "200": {description: Durable job state and progress}
  /api/v1/jobs/{jobID}/authorization:
    get:
      summary: Retrieve the stored job authorization revision and digest
      description: Requires the operational bearer token. The digest identifies the stored envelope without disclosing it; expired authorizations remain visible for reconciliation and do not enable execution.
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
      responses:
        "200":
          description: Revision zero and null expiry indicate that no authorization was stored
          content:
            application/json:
              schema:
                type: object
                required: [revision, expires_at, envelope_digest, execution_enabled]
                properties:
                  revision: {type: integer, minimum: 0}
                  expires_at: {type: [string, "null"], format: date-time}
                  envelope_digest: {type: string, description: Unpadded base64url SHA-256 digest, or empty when revision is zero}
                  execution_enabled: {type: boolean, description: True when this node runs jobs bound to signed authorizations}
        "401": {description: Invalid operational bearer token}
        "404": {description: Job not found}
        "503": {description: Durable state unavailable or inconsistent}
    post:
      summary: Register or renew a signed job authorization
      description: Requires the operational bearer token and a signed, job-bound envelope. The node verifies the job scope and next revision and stores the context encrypted. A local copy waiting for authorization is queued; a running one keeps running while its lease is renewed.
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Access-Authorization, required: true, schema: {type: string}}
      responses:
        "200":
          description: Authorization registered or an identical current envelope retried
          content:
            application/json:
              schema:
                type: object
                required: [revision, expires_at, execution_enabled]
                properties:
                  revision: {type: integer, minimum: 1}
                  expires_at: {type: string, format: date-time}
                  execution_enabled: {type: boolean, description: True when this node runs jobs bound to signed authorizations}
        "400": {description: Missing or ambiguous signed envelope}
        "401": {description: Invalid operational bearer token}
        "403": {description: Invalid, expired, replayed or mismatched authorization}
        "503": {description: Signing keys or durable state unavailable}
  /api/v1/jobs/{jobID}/items:
    get:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
        - {in: query, name: after, schema: {type: integer, minimum: 0}}
        - {in: query, name: limit, schema: {type: integer, maximum: 500}}
      responses:
        "200": {description: Persistent manifest items and per-file results}
  /api/v1/jobs/{jobID}/items/{ordinal}/override:
    post:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
        - {in: path, name: ordinal, required: true, schema: {type: integer, minimum: 0}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [action]
              properties:
                action: {type: string, enum: [skip, overwrite, rename, fail]}
                apply_to_following: {type: boolean}
      responses:
        "200": {description: Override persisted; job requeued when all conflicts have decisions}
  /api/v1/jobs/{jobID}/pause:
    post:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
      responses:
        "200": {description: Job paused or pause requested}
  /api/v1/jobs/{jobID}/resume:
    post:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
      responses:
        "200": {description: Paused or interrupted job queued again}
  /api/v1/jobs/{jobID}/cancel:
    post:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
      responses:
        "200": {description: Job canceled or cancellation requested}
  /api/v1/jobs/{jobID}/retry:
    post:
      parameters:
        - {in: path, name: jobID, required: true, schema: {type: string}}
      responses:
        "200": {description: Failed job queued with a fresh retry budget}
  /api/v1/pairing/invites:
    get:
      responses:
        "200": {description: Pairing invitations without secret material}
    post:
      responses:
        "201": {description: One-time pairing invitation}
  /api/v1/pairing/requests:
    get:
      responses:
        "200": {description: Incoming pairing requests awaiting review}
    post:
      responses:
        "201": {description: Pairing request recorded without creating trust or grants}
  /api/v1/peers:
    get:
      responses:
        "200": {description: Explicitly trusted peers}
  /api/v1/peers/{peerNodeID}:
    patch:
      description: Update peer control and mTLS endpoints without changing its trusted identity
      parameters:
        - {in: path, name: peerNodeID, required: true, schema: {type: string}}
      responses:
        "200": {description: Endpoints updated and peer returned to unknown until authenticated heartbeat}
        "400": {description: Invalid endpoint or revoked peer}
        "404": {description: Peer not found}
    delete:
      description: Revoke peer trust, disable its grants, and cancel related active jobs
      parameters:
        - {in: path, name: peerNodeID, required: true, schema: {type: string}}
      responses:
        "200": {description: Peer revoked and related job cancellation initiated}
        "404": {description: Peer not found}
  /api/v1/peers/{peerNodeID}/identity:
    patch:
      description: Manually confirm a changed peer fingerprint before restoring trust
      parameters:
        - {in: path, name: peerNodeID, required: true, schema: {type: string}}
      responses:
        "200": {description: New fingerprint recorded; authenticated heartbeat is still required}
        "400": {description: Peer is not in identity_changed or confirmation is invalid}
  /api/v1/peers/{peerNodeID}/identity/handover:
    patch:
      description: Apply a dual-signed consecutive identity epoch without changing the trusted node_id
      parameters:
        - {in: path, name: peerNodeID, required: true, schema: {type: string}}
      responses:
        "200": {description: Trusted peer advanced to the next identity epoch; authenticated heartbeat is still required}
        "400": {description: Handover is invalid, tampered, replayed, or does not continue the exact trusted epoch}
        "404": {description: Peer not found}
  /api/v1/crypto/identity:
    get:
      responses:
        "200": {description: Safe active and persisted identity metadata}
  /api/v1/crypto/identity/handovers:
    get:
      description: Return the durable public chain of signed identity handovers
      responses:
        "200": {description: Ordered handover envelopes without private key material}
  /api/v1/crypto/identity/rotate:
    post:
      description: Rotate the Ed25519 key, preserve node_id, advance the epoch, and emit a dual-signed handover; restart is required
      responses:
        "202": {description: New identity and handover persisted and previous identity archived}
        "409": {description: Fingerprint confirmation mismatch or restart already required}
  /api/v1/crypto/operational-token:
    get:
      responses:
        "200": {description: Secret-free operational token rotation state}
  /api/v1/crypto/operational-token/prepare:
    post:
      description: Stage the SHA-256 digest of a new operational token while preserving current access
      responses:
        "202": {description: New token prepared and accepted in parallel}
        "400": {description: New token is too short}
  /api/v1/crypto/operational-token/commit:
    post:
      description: Promote the authenticated staged token and invalidate the environment token
      responses:
        "200": {description: New token active and old token invalidated}
        "409": {description: Authenticated token was not prepared}
  /api/v1/transfers/pull:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [peer_node_id, source_grant_id, source_path, destination_grant_id, destination_path]
              properties:
                peer_node_id: {type: string}
                source_grant_id: {type: string}
                source_path: {type: string}
                destination_grant_id: {type: string}
                destination_path: {type: string}
                conflict_policy: {type: string, enum: [skip, overwrite, rename, fail, checksum]}
                verify_checksum: {type: boolean}
                bandwidth_limit_bytes_per_second: {type: integer, format: int64, minimum: 0}
                max_parallel_files: {type: integer, minimum: 1, maximum: 32}
                max_parallel_chunks: {type: integer, minimum: 1, maximum: 16}
      responses:
        "201": {description: Durable direct node-to-node pull job queued on the destination node}
        "403": {description: Exact-peer source or destination grant does not authorize the transfer}
  /api/v1/transfers/pull/directory/plan:
    post:
      description: Fetches a paginated manifest over mTLS and compares it with the destination without creating a job
      responses:
        "200": {description: Itemized remote directory preview with aggregate byte and file counts}
        "403": {description: Exact-peer source or destination grant does not authorize the preview}
  /api/v1/transfers/pull/directory:
    post:
      description: Atomically persists an itemized remote directory plan and queues its destination-owned job
      responses:
        "201": {description: Durable remote directory pull job queued}
        "403": {description: Exact-peer source or destination grant does not authorize the transfer}
  /api/v1/transfers/pull/batch/plan:
    post:
      description: Node-internal grant-relative batch preview. The Control Tower public API resolves grants before invoking this route.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [peer_node_id, source_grant_id, source_paths, destination_grant_id, destination_path, operation]
              properties:
                peer_node_id: {type: string}
                source_grant_id: {type: string}
                source_paths: {type: array, minItems: 1, items: {type: string}}
                source_names: {type: array, description: Mount-relative display names for source_paths; required when a path is exactly the grant root, items: {type: string}}
                destination_grant_id: {type: string}
                destination_path: {type: string}
                operation: {type: string, enum: [copy, move]}
                conflict_policy: {type: string, enum: [skip, overwrite, rename, fail, ask, checksum], default: fail}
                verify_checksum: {type: boolean}
      responses:
        "200": {description: Complete totals and an item preview truncated to 500 entries when necessary}
  /api/v1/transfers/signed-pull/batch/prepare:
    post:
      summary: Normalizes a node-to-node copy into the options a lease binds
      description: Requires the operational bearer token. It plans and creates nothing. A move is accepted too and needs a plan. Previewing it records a one-use confirmation (move_plan) that creation must present. Available when the node runs signed jobs.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [peer_node_id, source_grant_id, source_paths, destination_grant_id, destination_path]
              properties:
                peer_node_id: {type: string}
                source_grant_id: {type: string}
                source_paths: {type: array, items: {type: string}, description: Paths relative to the source grant}
                source_names: {type: array, items: {type: string}}
                destination_grant_id: {type: string}
                destination_path: {type: string}
                operation: {type: string, enum: [copy, move]}
                subject_type: {type: string, enum: [user, service_account], description: Only for a move; the subject the Control Tower authenticated}
                plan_id: {type: string, description: Only when creating a move; the plan it consumes}
                plan_token: {type: string, description: Only when creating a move}
                conflict_policy: {type: string, enum: [skip, overwrite, rename, fail, checksum]}
                verify_checksum: {type: boolean}
                bandwidth_limit_bytes_per_second: {type: integer}
                max_parallel_files: {type: integer}
                max_parallel_chunks: {type: integer}
      responses:
        "200": {description: Normalized options, digest and execution_enabled}
        "400": {description: Invalid request, a move, or the ask conflict policy}
        "503": {description: Signed transfers unavailable on this node}
  /api/v1/transfers/signed-pull/batch/plan:
    post:
      summary: Previews a node-to-node copy under a signed lease
      description: Requires the operational bearer token and a job-bound signed envelope. It creates nothing. The preview lists only the entries the signed policy lets the actor list and read and reports how many it left out (sources_omitted), never their names.
      parameters:
        - {in: header, name: X-Jolt-Access-Authorization, required: true, schema: {type: string}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [peer_node_id, source_grant_id, source_paths, destination_grant_id, destination_path]
              properties:
                peer_node_id: {type: string}
                source_grant_id: {type: string}
                source_paths: {type: array, items: {type: string}}
                destination_grant_id: {type: string}
                destination_path: {type: string}
                conflict_policy: {type: string}
      responses:
        "200": {description: Counts and the first 500 permitted items, with sources_omitted}
        "400": {description: Invalid request, scope or signature}
        "503": {description: Signed transfers unavailable on this node}
  /api/v1/transfers/signed-pull/batch:
    post:
      summary: Plans a node-to-node copy under a signed lease and creates it awaiting authorization
      description: Requires the operational bearer token, a job-bound signed envelope and an Idempotency-Key. The plan keeps only the source entries the signed policy lets the actor list and read (the count of omitted entries is recorded, never their names) and fails if a destination is not writable under it. The job is queued once its first authorization is registered and runs only while that authorization is renewed.
      parameters:
        - {in: header, name: X-Jolt-Access-Authorization, required: true, schema: {type: string}}
        - {in: header, name: Idempotency-Key, required: true, schema: {type: string, maxLength: 128}}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [peer_node_id, source_grant_id, source_paths, destination_grant_id, destination_path]
              properties:
                peer_node_id: {type: string}
                source_grant_id: {type: string}
                source_paths: {type: array, items: {type: string}, description: Paths relative to the source grant}
                source_names: {type: array, items: {type: string}}
                destination_grant_id: {type: string}
                destination_path: {type: string}
                operation: {type: string, enum: [copy]}
                conflict_policy: {type: string, enum: [skip, overwrite, rename, fail, checksum]}
                verify_checksum: {type: boolean}
                bandwidth_limit_bytes_per_second: {type: integer}
                max_parallel_files: {type: integer}
                max_parallel_chunks: {type: integer}
      responses:
        "200": {description: Existing job returned for an identical request}
        "202": {description: Job created in waiting_validation}
        "400": {description: Invalid request, scope or signature}
        "403": {description: A grant or the peer does not permit the transfer}
        "409": {description: Idempotency key or job identifier conflict}
        "503": {description: Signed transfers unavailable on this node}
  /api/v1/transfers/pull/batch:
    post:
      description: Persists one destination-owned batch job. Move forces checksum verification and source removal is requested only after every item has completed.
      parameters:
        - {in: header, name: Idempotency-Key, required: true, schema: {type: string}}
        - {in: header, name: X-Jolt-Idempotency-Hash, schema: {type: string, description: Canonical logical request hash from the Control Tower}}
      responses:
        "201": {description: New durable batch job}
        "200": {description: Existing job for the same idempotency key and payload}
        "409": {description: Idempotency key was reused with a different payload}
  /peer/v1/heartbeat:
    get:
      description: Available only on the mTLS listener and requires an exact trusted peer certificate
      responses:
        "200": {description: Authenticated node liveness and identity payload}
  /peer/v1/grants/{grantID}/content:
    get:
      description: Range-capable file stream available only on the mTLS listener
      parameters:
        - {in: path, name: grantID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: checksum, schema: {type: boolean}}
      responses:
        "200": {description: Full grant-scoped file stream}
        "206": {description: Partial stream used to resume a durable transfer}
        "403": {description: Certificate identity is not authorized by the exact source grant}
  /peer/v1/grants/{grantID}/manifest:
    get:
      description: Paginated grant-scoped directory manifest available only on the mTLS listener
      parameters:
        - {in: path, name: grantID, required: true, schema: {type: string}}
        - {in: query, name: path, required: true, schema: {type: string}}
        - {in: query, name: after, schema: {type: integer, minimum: 0}}
        - {in: query, name: limit, schema: {type: integer, minimum: 1, maximum: 1000}}
        - {in: query, name: checksum, schema: {type: boolean}}
      responses:
        "200": {description: Stable manifest page containing relative paths, types, sizes, mtimes, and optional checksums}
        "403": {description: Certificate identity is not authorized by the exact source grant}
  /api/v1/crypto/mtls:
    get:
      responses:
        "200": {description: Safe active, next, previous, revocation, rollout acknowledgement, and accepted peer certificate metadata; private keys are never returned}
  /api/v1/crypto/mtls/rollout:
    get:
      description: Export the prepared next certificate and its safe public PEM for peer rollout
      responses:
        "200": {description: Identity-bound public certificate rollout envelope}
        "409": {description: No certificate rotation is pending}
  /api/v1/crypto/mtls/rollout/deliveries:
    post:
      description: Persist an acknowledgement or delivery failure for one peer in the pending rollout
      responses:
        "200": {description: Updated durable rollout diagnostics}
        "400": {description: Peer is not part of the selected rollout}
  /api/v1/peers/{peerNodeID}/mtls/rollout:
    patch:
      description: Validate and durably register a trusted peer's identity-bound next public certificate
      parameters:
        - {in: path, name: peerNodeID, required: true, schema: {type: string}}
      responses:
        "200": {description: Public certificate accepted for the exact trusted peer}
        "400": {description: Envelope is malformed, tampered, or does not match the trusted identity}
  /api/v1/crypto/mtls/rotate:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                validity_days: {type: integer, minimum: 1, maximum: 1825, default: 365}
      responses:
        "201": {description: A new identity-bound certificate was persisted in the next slot}
        "409": {description: A rotation is already pending}
  /api/v1/crypto/mtls/promote:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                grace_hours: {type: integer, minimum: 0, maximum: 720}
      responses:
        "200": {description: Next certificate atomically promoted; old certificate retained as previous}
        "409": {description: No rotation is pending}
  /api/v1/crypto/mtls/rollback:
    post:
      responses:
        "200": {description: Previous certificate restored while its grace window is active}
        "409": {description: No valid previous certificate is available for rollback}
  /api/v1/crypto/mtls/revoke:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [serial]
              properties:
                serial: {type: string}
                reason: {type: string}
      responses:
        "204": {description: Certificate serial persistently revoked for new connections}
  /api/v1/grants:
    get:
      responses:
        "200":
          description: Configured grants and effective authorization status
          content:
            application/json:
              schema:
                type: object
                properties:
                  items:
                    type: array
                    items: {$ref: '#/components/schemas/Grant'}
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [peer_node_id, mount_id, path, direction, permissions]
              properties:
                peer_node_id: {type: string}
                mount_id: {type: string}
                path: {type: string, description: Relative path inside an existing mount}
                direction: {type: string, enum: [send, receive, send_receive]}
                permissions:
                  type: object
                  properties:
                    read: {type: boolean}
                    write: {type: boolean}
                    delete: {type: boolean}
                    rename: {type: boolean}
                conflict_policies:
                  type: array
                  items: {type: string, enum: [skip, overwrite, rename, fail, ask, checksum]}
                visible_to_peer: {type: boolean}
                enabled: {type: boolean}
      responses:
        "409": {description: configuration_managed_by_file - edit node.yaml and restart}
  /api/v1/grants/{grantID}:
    patch:
      parameters:
        - {in: path, name: grantID, required: true, schema: {type: string}}
      responses:
        "409": {description: configuration_managed_by_file - edit node.yaml and restart}
    delete:
      parameters:
        - {in: path, name: grantID, required: true, schema: {type: string}}
      responses:
        "409": {description: configuration_managed_by_file - edit node.yaml and restart}
`

func (s *Server) signedExecutionEnabled() bool {
	return s.jobs != nil && s.jobs.SignedExecutionEnabled()
}

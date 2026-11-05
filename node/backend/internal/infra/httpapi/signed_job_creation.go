package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
	"github.com/jfxdev/jolt/backend/internal/services/jobs"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

type signedJobCreationStore interface {
	CreateJobAwaitingAuthorization(context.Context, entities.Job, string, string, string, string) (entities.Job, bool, error)
}

type signedLocalCopyRequest struct {
	MountID            string `json:"mount_id"`
	Source             string `json:"source_path"`
	Destination        string `json:"destination_path"`
	Overwrite          bool   `json:"overwrite"`
	Recursive          bool   `json:"recursive"`
	ConflictPolicy     string `json:"conflict_policy"`
	SourceChangePolicy string `json:"source_change_policy"`
	VerifyChecksum     bool   `json:"verify_checksum"`
	BandwidthLimit     int64  `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int    `json:"max_parallel_files"`
	MaxParallelChunks  int    `json:"max_parallel_chunks"`
	MaxAttempts        int    `json:"max_attempts"`
}

func (request signedLocalCopyRequest) createRequest(correlation string) jobs.CreateRequest {
	return jobs.CreateRequest{Type: "copy_local", MountID: request.MountID, SourcePath: request.Source, Destination: request.Destination, CorrelationID: correlation, Overwrite: request.Overwrite, Recursive: request.Recursive, ConflictPolicy: request.ConflictPolicy, SourceChangePolicy: request.SourceChangePolicy, VerifyChecksum: request.VerifyChecksum, BandwidthLimit: request.BandwidthLimit, MaxParallelFiles: request.MaxParallelFiles, MaxParallelChunks: request.MaxParallelChunks, MaxAttempts: request.MaxAttempts}
}

func decodeSignedLocalCopy(w http.ResponseWriter, r *http.Request) (signedLocalCopyRequest, bool) {
	var request signedLocalCopyRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || filetypes.ValidateUniqueJSON(body) != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.", nil)
		return request, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.", nil)
		return request, false
	}
	return request, true
}

func (s *Server) prepareSignedLocalCopy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.store.(signedJobCreationStore); !ok || len(s.config.AuthorizationKeys) == 0 {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_creation_unavailable", "A criação de jobs assinados está indisponível.", nil)
		return
	}
	request, ok := decodeSignedLocalCopy(w, r)
	if !ok {
		return
	}
	options, digest, err := s.jobs.PrepareSignedLocalCopy(r.Context(), request.createRequest(r.Header.Get("X-Correlation-ID")))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Jolt-Signed-Job-Preparation", "v1")
	writeJSON(w, http.StatusOK, map[string]any{"options": options, "options_digest": digest, "execution_enabled": s.signedExecutionEnabled()})
}

func (s *Server) createSignedLocalCopy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.store.(signedJobCreationStore); !ok || len(s.config.AuthorizationKeys) == 0 {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_creation_unavailable", "A criação de jobs assinados está indisponível.", nil)
		return
	}
	authorizations, idempotencies := r.Header.Values(signedAuthorizationHeader), r.Header.Values("Idempotency-Key")
	if len(authorizations) != 1 || authorizations[0] == "" || len(idempotencies) != 1 || strings.TrimSpace(idempotencies[0]) != idempotencies[0] || !signedauth.ValidKeyID(idempotencies[0]) {
		writeError(w, r, http.StatusBadRequest, "invalid_signed_context", "Informe uma autorização assinada e uma chave de idempotência válida.", nil)
		return
	}
	request, ok := decodeSignedLocalCopy(w, r)
	if !ok {
		return
	}
	job, repeated, err := s.jobs.CreateAwaitingSignedAuthorization(r.Context(), request.createRequest(r.Header.Get("X-Correlation-ID")), s.identity.NodeID, authorizations[0], idempotencyKey(r), s.config.AuthorizationKeys)
	if errors.Is(err, contracts.ErrIdempotencyConflict) || errors.Is(err, contracts.ErrInUse) {
		writeError(w, r, http.StatusConflict, "signed_job_conflict", "A chave ou o identificador do job já está em uso.", nil)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Jolt-Signed-Job-Creation", "v1")
	status := http.StatusAccepted
	if repeated {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"job": job, "execution_enabled": s.signedExecutionEnabled()})
}

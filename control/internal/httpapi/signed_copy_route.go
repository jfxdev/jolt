package httpapi

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// signedLocalCopyMount returns the mount of a local copy request when the
// resource is mounts/{mountID}/files/copy.
func signedLocalCopyMount(resource string) (string, bool) {
	segments := strings.Split(resource, "/")
	if len(segments) != 4 || segments[0] != "mounts" || segments[2] != "files" || segments[3] != "copy" || !validPathIdentifier(segments[1]) {
		return "", false
	}
	return segments[1], true
}

// createSignedLocalCopyFromRequest creates a local copy as a job bound to the
// caller's current authorization. The caller already passed the coarse path
// permissions; the node enforces the exact policy context while the job runs.
func (s *Server) createSignedLocalCopyFromRequest(w http.ResponseWriter, r *http.Request, node store.Node, mountID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.")
		return
	}
	var request struct {
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
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "A solicitação não é um JSON válido.")
		return
	}
	if strings.ToLower(strings.TrimSpace(request.ConflictPolicy)) == "ask" {
		writeError(w, r, http.StatusUnprocessableEntity, "conflict_policy_unsupported", "Cópias protegidas não aceitam a política \"ask\". Escolha skip, overwrite, rename, fail ou checksum.")
		return
	}
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotency == "" {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			s.fail(w, r, err)
			return
		}
		idempotency = "copy-" + hex.EncodeToString(random[:])
	}
	if !signedauth.ValidKeyID(idempotency) {
		writeError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "A chave de idempotência é inválida.")
		return
	}
	input := store.SignedCopyRequest{
		MountID: mountID, Source: request.SourcePath, Destination: request.DestinationPath, Overwrite: request.Overwrite,
		ConflictPolicy: request.ConflictPolicy, SourceChangePolicy: request.SourceChangePolicy, VerifyChecksum: request.VerifyChecksum,
		BandwidthLimit: request.BandwidthLimit, MaxParallelFiles: request.MaxParallelFiles, MaxParallelChunks: request.MaxParallelChunks,
	}
	jobID, err := s.createSignedLocalCopy(r, node.ID, idempotency, input)
	if err != nil {
		s.audit(r, "create", "nodes/"+node.ID+"/mounts/"+mountID+"/files/copy", "failed")
		if errors.Is(err, errSignedJobRegistrationUnavailable) {
			writeError(w, r, http.StatusServiceUnavailable, "signed_job_unavailable", "Não foi possível criar a cópia protegida. Verifique a versão do node e as permissões atuais.")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.audit(r, "create", "nodes/"+node.ID+"/jobs/"+jobID, "allowed")
	// Deliver the first lease now instead of waiting for the renewal loop. A
	// failure here is harmless: the loop retries it within seconds.
	_, _ = s.renewSignedLocalJobLease(r.Context(), node.ID, jobID)
	var job json.RawMessage
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "A cópia foi criada, mas o estado do job não pôde ser lido.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/nodes/"+url.PathEscape(node.ID)+"/jobs/"+url.PathEscape(jobID))
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(job)
}

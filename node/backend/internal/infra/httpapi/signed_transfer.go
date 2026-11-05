package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/signedauth"
)

// prepareSignedBatchPull returns the normalized options a lease for a
// node-to-node copy binds. It plans and creates nothing.
func (s *Server) prepareSignedBatchPull(w http.ResponseWriter, r *http.Request) {
	if !s.signedExecutionEnabled() || s.transfers == nil {
		writeError(w, r, http.StatusServiceUnavailable, "signed_transfer_unavailable", "As transferências assinadas estão indisponíveis neste node.", nil)
		return
	}
	var request batchPullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	options, digest, err := s.transfers.PrepareSignedBatchPull(r.Context(), request.transferRequest(r.Header.Get("X-Correlation-ID")))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Jolt-Signed-Transfer-Preparation", "v1")
	writeJSON(w, http.StatusOK, map[string]any{"options": options, "options_digest": digest, "execution_enabled": true})
}

// createSignedBatchPull plans the copy under the filter of the signed lease and
// persists the job awaiting that authorization.
func (s *Server) createSignedBatchPull(w http.ResponseWriter, r *http.Request) {
	if !s.signedExecutionEnabled() || s.transfers == nil {
		writeError(w, r, http.StatusServiceUnavailable, "signed_transfer_unavailable", "As transferências assinadas estão indisponíveis neste node.", nil)
		return
	}
	authorizations, idempotencies := r.Header.Values(signedAuthorizationHeader), r.Header.Values("Idempotency-Key")
	if len(authorizations) != 1 || authorizations[0] == "" || len(idempotencies) != 1 || strings.TrimSpace(idempotencies[0]) != idempotencies[0] || !signedauth.ValidKeyID(idempotencies[0]) {
		writeError(w, r, http.StatusBadRequest, "invalid_signed_context", "Informe uma autorização assinada e uma chave de idempotência válida.", nil)
		return
	}
	var request batchPullTransferRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	job, repeated, err := s.transfers.CreateSignedBatchPull(r.Context(), request.transferRequest(r.Header.Get("X-Correlation-ID")), s.identity.NodeID, authorizations[0], idempotencies[0], s.config.AuthorizationKeys)
	if errors.Is(err, contracts.ErrIdempotencyConflict) || errors.Is(err, contracts.ErrInUse) {
		writeError(w, r, http.StatusConflict, "signed_job_conflict", "A chave ou o identificador do job já está em uso.", nil)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Jolt-Signed-Transfer-Creation", "v1")
	status := http.StatusAccepted
	if repeated {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"job": job, "execution_enabled": true})
}

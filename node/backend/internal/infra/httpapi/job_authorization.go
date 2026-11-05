package httpapi

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
)

type signedJobAuthorizationRegistrar interface {
	RegisterSignedJobAuthorization(context.Context, string, string, string, map[string]ed25519.PublicKey, time.Time) (uint64, time.Time, error)
}

// registerJobAuthorization records a signed lease but does not authorize job
// execution. Jobs remain waiting until policy and renewal integration exists.
func (s *Server) registerJobAuthorization(w http.ResponseWriter, r *http.Request) {
	registrar, ok := s.store.(signedJobAuthorizationRegistrar)
	if !ok || len(s.config.AuthorizationKeys) == 0 {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_authorization_unavailable", "O node não pode registrar a autorização assinada.", nil)
		return
	}
	headers := r.Header.Values(signedAuthorizationHeader)
	if len(headers) != 1 || headers[0] == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_signed_context", "Informe uma autorização assinada.", nil)
		return
	}
	revision, expiry, err := registrar.RegisterSignedJobAuthorization(r.Context(), r.PathValue("jobID"), s.identity.NodeID, headers[0], s.config.AuthorizationKeys, time.Now().UTC())
	if err != nil {
		if errors.Is(err, contracts.ErrStateUnavailable) {
			writeError(w, r, http.StatusServiceUnavailable, "state_unavailable", "O estado do node está indisponível.", nil)
			return
		}
		if errors.Is(err, contracts.ErrInUse) || errors.Is(err, contracts.ErrNotFound) {
			writeError(w, r, http.StatusForbidden, "invalid_signed_context", "A autorização é inválida, expirada ou incompatível com o job.", nil)
			return
		}
		s.fail(w, r, err)
		return
	}
	w.Header().Set("X-Jolt-Job-Authorization-Applied", "v1")
	writeJSON(w, http.StatusOK, map[string]any{"revision": revision, "expires_at": expiry, "execution_enabled": false})
}

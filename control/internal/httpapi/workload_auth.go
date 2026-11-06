package httpapi

import (
	"net/http"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
	"github.com/jfxdev/jolt/control/internal/workload"
)

const workloadIdentityKey contextKey = "verified_workload_identity"

// revalidateServiceCredential uses only a verified identity from the request
// context. The raw bearer JWT is never persisted in that context or the store.
func (s *Server) revalidateServiceCredential(r *http.Request) (store.ServiceAccount, store.ServiceAccountToken, error) {
	if identity, ok := r.Context().Value(workloadIdentityKey).(workload.Identity); ok {
		if s.config.WorkloadProviders == nil || !s.config.WorkloadProviders.AllowsMapping(identity.ProviderID, identity.Issuer, identity.Subject, identity.Audience) {
			return store.ServiceAccount{}, store.ServiceAccountToken{}, store.ErrNotFound
		}
		return s.store.AuthenticateWorkloadIdentity(r.Context(), identity.ProviderID, identity.Issuer, identity.Subject, identity.Audience, identity.ExpiresAt, time.Now().UTC())
	}
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if digest == "" {
		return store.ServiceAccount{}, store.ServiceAccountToken{}, store.ErrNotFound
	}
	return s.store.AuthenticateServiceAccount(r.Context(), digest)
}

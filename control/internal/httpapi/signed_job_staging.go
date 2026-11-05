package httpapi

import (
	"crypto/ed25519"
	"math"
	"net/http"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
)

// stageSignedLocalJobLease prepares the next revision for an existing link.
// It does not deliver the envelope or enable job execution. A separate retry
// step rechecks current permissions before sending the persisted envelope.
func (s *Server) stageSignedLocalJobLease(r *http.Request, nodeID, jobID string) (uint64, error) {
	fail := func() (uint64, error) { return 0, errSignedJobRegistrationUnavailable }
	if !validPathIdentifier(nodeID) || !validPathIdentifier(jobID) || len(s.config.AuthorizationSigningKey) != ed25519.PrivateKeySize {
		return fail()
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		return fail()
	}
	link, err := s.store.GetJobAuthorizationLink(r.Context(), nodeID, jobID)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if err != nil || !currentUser(r).Enabled || currentUser(r).ID != link.ActorID || currentActorType(r) != link.ActorType || credential != link.CredentialID || digest != link.CredentialDigest {
		return fail()
	}
	state, err := s.reconcileSignedJobAuthorization(r, node, jobID)
	if err != nil {
		return fail()
	}
	link, err = s.store.GetJobAuthorizationLink(r.Context(), nodeID, jobID)
	if err != nil {
		return fail()
	}
	if state == signedJobPendingDelivery {
		return fail()
	}
	if link.PendingRevision != 0 || link.ConfirmedRevision >= math.MaxInt64 {
		return fail()
	}
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		return fail()
	}
	if info.NodeID != nodeID || !supportsSignedJobRegistration(info.Capabilities) {
		return fail()
	}
	var job signedLocalJob
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, r.Header.Get("X-Correlation-ID")); err != nil || job.ID != jobID {
		return fail()
	}
	now := time.Now().UTC()
	revision := link.ConfirmedRevision + 1
	envelope, err := s.issueSignedLocalJobLease(r, nodeID, job, revision, now)
	if err != nil {
		return fail()
	}
	keys := map[string]ed25519.PublicKey{s.config.AuthorizationSigningKeyID: s.config.AuthorizationSigningKey.Public().(ed25519.PublicKey)}
	if _, _, err := signedauth.VerifyJobLease(envelope, keys, link.Binding, nodeID, revision, now); err != nil {
		return fail()
	}
	if _, err := s.store.StageJobAuthorization(r.Context(), nodeID, jobID, revision, envelope, keys, time.Now().UTC()); err != nil {
		return fail()
	}
	return revision, nil
}

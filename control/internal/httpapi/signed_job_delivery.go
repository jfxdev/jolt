package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

// deliverPendingSignedJobLease is internal groundwork. It retries only the
// exact durable envelope after independently reconstructing current access.
// It does not create a link, start renewal, or enable job execution.
func (s *Server) deliverPendingSignedJobLease(r *http.Request, nodeID, jobID string) (signedJobReconciliation, error) {
	fail := func() (signedJobReconciliation, error) { return 0, errSignedJobRegistrationUnavailable }
	if !validPathIdentifier(nodeID) || !validPathIdentifier(jobID) {
		return fail()
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		return fail()
	}
	link, err := s.store.GetJobAuthorizationLink(r.Context(), node.ID, jobID)
	if err != nil || !currentUser(r).Enabled || currentUser(r).ID != link.ActorID || currentActorType(r) != link.ActorType {
		return fail()
	}
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if credential != link.CredentialID || digest != link.CredentialDigest || len(s.signingKey()) != ed25519.PrivateKeySize {
		return fail()
	}
	state, err := s.reconcileSignedJobAuthorization(r, node, jobID)
	if err != nil {
		return fail()
	}
	if state != signedJobPendingDelivery {
		return state, nil
	}
	link, err = s.store.GetJobAuthorizationLink(r.Context(), node.ID, jobID)
	if err != nil || link.PendingRevision == 0 {
		return fail()
	}
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		return fail()
	}
	if info.NodeID != node.ID || !supportsSignedJobRegistration(info.Capabilities) {
		return fail()
	}
	var job signedLocalJob
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, r.Header.Get("X-Correlation-ID")); err != nil || job.ID != jobID {
		return fail()
	}
	now := time.Now().UTC()
	fresh, err := s.issueSignedJobLease(r, node.ID, job, link.PendingRevision, now)
	if err != nil {
		return fail()
	}
	keys := s.verificationKeys()
	pendingClaims, _, err := signedauth.VerifyJobLease(link.PendingEnvelope, keys, link.Binding, node.ID, link.PendingRevision, now)
	if err != nil || !time.Unix(pendingClaims.ExpiresAt, 0).Equal(link.PendingExpiry) {
		return fail()
	}
	freshClaims, _, err := signedauth.VerifyJobLease(fresh, keys, link.Binding, node.ID, link.PendingRevision, now)
	if err != nil || freshClaims.ExpiresAt < pendingClaims.ExpiresAt || !bytes.Equal(freshClaims.Context, pendingClaims.Context) {
		return fail()
	}
	if _, err := s.store.StageJobAuthorization(r.Context(), node.ID, jobID, link.PendingRevision, link.PendingEnvelope, keys, time.Now().UTC()); err != nil {
		return fail()
	}
	expiry, err := s.sendSignedJobLease(r, node, jobID, link.PendingRevision, link.PendingEnvelope, link.PendingExpiry)
	if err != nil {
		return fail()
	}
	if err := s.store.ConfirmJobAuthorization(r.Context(), node.ID, jobID, link.PendingRevision, security.Digest(link.PendingEnvelope), expiry, time.Now().UTC()); err != nil {
		return fail()
	}
	return signedJobConfirmed, nil
}

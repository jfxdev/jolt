package httpapi

import (
	"crypto/ed25519"
	"net/http"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// bindSignedLocalJob derives the durable actor and scope from the current
// authenticated request and a registered node. It is internal groundwork;
// binding alone neither modifies the node job nor enables execution.
func (s *Server) bindSignedLocalJob(r *http.Request, nodeID, jobID string) error {
	fail := func() error { return errSignedJobRegistrationUnavailable }
	if !validPathIdentifier(nodeID) || !validPathIdentifier(jobID) || len(s.signingKey()) != ed25519.PrivateKeySize {
		return fail()
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		return fail()
	}
	status, err := s.signedJobStatus(r, node, jobID)
	if err != nil || status.Revision != 0 {
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
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, r.Header.Get("X-Correlation-ID")); err != nil || job.ID != jobID || (job.State != "paused" && job.State != "waiting_validation" && job.State != "interrupted") {
		return fail()
	}
	now := time.Now().UTC()
	envelope, err := s.issueSignedJobLease(r, nodeID, job, 1, now)
	if err != nil {
		return fail()
	}
	keys := s.verificationKeys()
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
	if err != nil {
		return fail()
	}
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	actor := currentUser(r)
	link := store.JobAuthorizationLink{NodeID: nodeID, JobID: jobID, ActorType: currentActorType(r), ActorID: actor.ID, CredentialID: credential, CredentialDigest: digest, Binding: binding}
	if err := s.store.CreateJobAuthorizationLink(r.Context(), link, time.Now().UTC()); err != nil {
		return fail()
	}
	return nil
}

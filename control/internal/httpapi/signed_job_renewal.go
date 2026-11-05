package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/jfxdev/jolt/control/internal/store"
)

// signedJobRenewalRequest reconstructs only persisted credential identity,
// never a bearer token. Current account and policy state are checked again by
// the issuer and store before any lease is sent.
func (s *Server) signedJobRenewalRequest(ctx context.Context, link store.JobAuthorizationLink) (*http.Request, error) {
	var actor store.User
	switch link.ActorType {
	case "user":
		current, _, err := s.store.SessionUserAndExpiry(ctx, link.CredentialDigest)
		if err != nil || !current.Enabled || current.ID != link.ActorID || !strings.HasPrefix(link.CredentialID, "session-") {
			return nil, errSignedJobRegistrationUnavailable
		}
		actor = current
	case "service_account":
		account, token, err := s.store.AuthenticateServiceAccount(ctx, link.CredentialDigest)
		if err != nil || !account.Enabled || account.Kind != "automation" || account.ID != link.ActorID || link.CredentialID != "token-"+token.ID {
			return nil, errSignedJobRegistrationUnavailable
		}
		actor = store.User{ID: account.ID, Username: account.Name, Role: "service_account", Enabled: true}
	default:
		return nil, errSignedJobRegistrationUnavailable
	}
	ctx = context.WithValue(ctx, userKey, actor)
	ctx = context.WithValue(ctx, actorTypeKey, link.ActorType)
	ctx = context.WithValue(ctx, credentialKey, link.CredentialID)
	ctx = context.WithValue(ctx, credentialDigestKey, link.CredentialDigest)
	return http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/internal/job-renewal", nil)
}

// renewSignedLocalJob is a single internal renewal attempt, not a scheduler.
// It never starts a job and currently accepts only jobs awaiting validation.
func (s *Server) renewSignedLocalJob(ctx context.Context, nodeID, jobID string) error {
	if !validPathIdentifier(nodeID) || !validPathIdentifier(jobID) {
		return errSignedJobRegistrationUnavailable
	}
	link, err := s.store.GetJobAuthorizationLink(ctx, nodeID, jobID)
	if err != nil {
		return errSignedJobRegistrationUnavailable
	}
	r, err := s.signedJobRenewalRequest(ctx, link)
	if err != nil {
		return errSignedJobRegistrationUnavailable
	}
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return errSignedJobRegistrationUnavailable
	}
	var job signedLocalJob
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, ""); err != nil || job.ID != jobID || job.State != "waiting_validation" {
		return errSignedJobRegistrationUnavailable
	}
	state, err := s.deliverPendingSignedJobLease(r, nodeID, jobID)
	if err != nil {
		return errSignedJobRegistrationUnavailable
	}
	if state == signedJobConfirmed {
		return nil
	}
	if _, err := s.stageSignedLocalJobLease(r, nodeID, jobID); err != nil {
		return errSignedJobRegistrationUnavailable
	}
	state, err = s.deliverPendingSignedJobLease(r, nodeID, jobID)
	if err != nil || state != signedJobConfirmed {
		return errSignedJobRegistrationUnavailable
	}
	return nil
}

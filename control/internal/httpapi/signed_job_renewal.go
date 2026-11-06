package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/control/internal/store"
)

const (
	// A lease lives at most signedauth.MaxLifetime (30 s); renewing every 10 s
	// leaves room for two lost attempts before a running job stops.
	signedJobRenewalInterval = 10 * time.Second
	signedJobRenewalTimeout  = 25 * time.Second
	signedJobRenewalBatch    = 1000
	signedJobRenewalWorkers  = 8
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

// finalSignedJobState reports node job states that never run again, so their
// authorization stops being renewed. A failed job is final here: retrying it
// needs a new job, because nothing would renew the old one.
func finalSignedJobState(state string) bool {
	switch state {
	case "completed", "completed_with_warnings", "failed", "canceled":
		return true
	}
	return false
}

// renewableSignedJobState lists states in which the node accepts a newer lease.
func renewableSignedJobState(state string) bool {
	switch state {
	case "queued", "running", "waiting_validation", "waiting_peer", "waiting_mount", "paused", "interrupted":
		return true
	}
	return false
}

// renewSignedLocalJob makes one renewal attempt for a linked node job.
func (s *Server) renewSignedLocalJob(ctx context.Context, nodeID, jobID string) error {
	_, err := s.renewSignedLocalJobLease(ctx, nodeID, jobID)
	return err
}

// renewSignedLocalJobLease delivers a pending lease or stages and delivers the
// next one, after rechecking the linked credential, groups and policies. It
// reports finished once the node job reached a final state or no longer exists.
func (s *Server) renewSignedLocalJobLease(ctx context.Context, nodeID, jobID string) (finished bool, err error) {
	if !validPathIdentifier(nodeID) || !validPathIdentifier(jobID) {
		return false, errSignedJobRegistrationUnavailable
	}
	link, err := s.store.GetJobAuthorizationLink(ctx, nodeID, jobID)
	if err != nil {
		return false, errSignedJobRegistrationUnavailable
	}
	node, err := s.store.GetNode(ctx, nodeID)
	if err != nil {
		return false, errSignedJobRegistrationUnavailable
	}
	var job signedLocalJob
	if err := s.callNodeJSON(ctx, node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, ""); err != nil {
		var apiErr *nodeAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return true, nil
		}
		return false, errSignedJobRegistrationUnavailable
	}
	if job.ID != jobID {
		return false, errSignedJobRegistrationUnavailable
	}
	if finalSignedJobState(job.State) {
		return true, nil
	}
	if !renewableSignedJobState(job.State) {
		// A pause or cancel is being applied; the next pass sees the result.
		return false, nil
	}
	r, err := s.signedJobRenewalRequest(ctx, link)
	if err != nil {
		return false, errSignedJobRegistrationUnavailable
	}
	state, err := s.deliverPendingSignedJobLease(r, nodeID, jobID)
	if err != nil {
		return false, errSignedJobRegistrationUnavailable
	}
	if state == signedJobConfirmed {
		return false, nil
	}
	if _, err := s.stageSignedLocalJobLease(r, nodeID, jobID); err != nil {
		return false, errSignedJobRegistrationUnavailable
	}
	state, err = s.deliverPendingSignedJobLease(r, nodeID, jobID)
	if err != nil || state != signedJobConfirmed {
		return false, errSignedJobRegistrationUnavailable
	}
	return false, nil
}

// runSignedJobRenewal keeps every active job's lease fresh until ctx ends.
func (s *Server) runSignedJobRenewal(ctx context.Context) {
	ticker := time.NewTicker(signedJobRenewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.renewActiveSignedJobs(ctx)
		}
	}
}

func (s *Server) renewActiveSignedJobs(ctx context.Context) {
	links, err := s.store.ListActiveJobAuthorizationLinks(ctx, signedJobRenewalBatch)
	if err != nil {
		s.log.Warn("list signed job links", "error", err)
		return
	}
	slots := make(chan struct{}, signedJobRenewalWorkers)
	var group sync.WaitGroup
	for _, link := range links {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		group.Add(1)
		go func(link store.JobAuthorizationLink) {
			defer group.Done()
			defer func() { <-slots }()
			attempt, cancel := context.WithTimeout(ctx, signedJobRenewalTimeout)
			defer cancel()
			finished, err := s.renewSignedLocalJobLease(attempt, link.NodeID, link.JobID)
			if err != nil {
				s.log.Warn("renew signed job authorization", "node_id", link.NodeID, "job_id", link.JobID)
				return
			}
			if finished {
				if err := s.store.FinishJobAuthorizationLink(ctx, link.NodeID, link.JobID, time.Now().UTC()); err != nil {
					s.log.Warn("finish signed job authorization", "node_id", link.NodeID, "job_id", link.JobID)
				}
			}
		}(link)
	}
	group.Wait()
}

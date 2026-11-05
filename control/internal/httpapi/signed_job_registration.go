package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

var errSignedJobRegistrationUnavailable = errors.New("signed job registration unavailable")

// registerSignedLocalJobLease obtains job metadata from the registered node,
// signs the current request actor's permissions, and requires explicit node
// confirmation. It is internal until durable actor links and the renewal loop
// exist; successful registration never enables job execution.
func (s *Server) registerSignedLocalJobLease(r *http.Request, node store.Node, jobID string, revision uint64) (time.Time, error) {
	if !validPathIdentifier(node.ID) || !validPathIdentifier(jobID) || revision == 0 {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	supported := false
	for _, capability := range info.Capabilities {
		supported = supported || capability == "signed_job_authorization_registration_v1"
	}
	if info.NodeID != node.ID || !supported {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	var job signedLocalJob
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &job, r.Header.Get("X-Correlation-ID")); err != nil || job.ID != jobID {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	now := time.Now().UTC()
	envelope, err := s.issueSignedLocalJobLease(r, node.ID, job, revision, now)
	if err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	keys := map[string]ed25519.PublicKey{s.config.AuthorizationSigningKeyID: s.config.AuthorizationSigningKey.Public().(ed25519.PublicKey)}
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, node.ID, now)
	if err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	claims, _, err := signedauth.VerifyJobLease(envelope, keys, binding, node.ID, revision, now)
	if err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	return s.sendSignedJobLease(r, node, jobID, revision, envelope, time.Unix(claims.ExpiresAt, 0).UTC())
}

// sendSignedJobLease only transports a previously validated envelope. The
// caller must establish its binding, current policy and durable revision.
func (s *Server) sendSignedJobLease(r *http.Request, node store.Node, jobID string, revision uint64, envelope string, expiry time.Time) (time.Time, error) {
	if !validPathIdentifier(node.ID) || !validPathIdentifier(jobID) || revision == 0 || envelope == "" || !expiry.After(time.Now().UTC()) || r.Context().Err() != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	nodeToken, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, node.Endpoint+"/api/v1/jobs/"+url.PathEscape(jobID)+"/authorization", nil)
	if err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+nodeToken)
	request.Header.Set(signedAuthorizationHeader, envelope)
	request.Header.Set("X-Correlation-ID", r.Header.Get("X-Correlation-ID"))
	response, err := s.client.Do(request)
	if err != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("X-Jolt-Job-Authorization-Applied")) != 1 || response.Header.Get("X-Jolt-Job-Authorization-Applied") != "v1" {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || filetypes.ValidateUniqueJSON(body) != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	var result struct {
		Revision         uint64    `json:"revision"`
		ExpiresAt        time.Time `json:"expires_at"`
		ExecutionEnabled *bool     `json:"execution_enabled"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Revision != revision || result.ExecutionEnabled == nil || *result.ExecutionEnabled || !result.ExpiresAt.Equal(expiry) || !result.ExpiresAt.After(time.Now().UTC()) || r.Context().Err() != nil {
		return time.Time{}, errSignedJobRegistrationUnavailable
	}
	return result.ExpiresAt, nil
}

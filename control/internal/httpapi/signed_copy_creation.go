package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// copyIntentJob builds only node-prepared metadata; the actor and access
// context are always derived separately from the authenticated request.
func copyIntentJob(id string, request store.SignedCopyRequest, options signedauth.JobOptions) signedLocalJob {
	return signedLocalJob{ID: id, Type: "copy_local", MountID: request.MountID, Source: request.Source, Destination: request.Destination, Overwrite: options.Overwrite, Recursive: options.Recursive, ConflictPolicy: options.ConflictPolicy, SourceChangePolicy: options.SourceChangePolicy, VerifyChecksum: options.VerifyChecksum, BandwidthLimit: options.BandwidthLimit, MaxParallelFiles: options.MaxParallelFiles, MaxParallelChunks: options.MaxParallelChunks, MaxAttempts: options.MaxAttempts}
}

func (s *Server) signedCopyNodeRequest(r *http.Request, node store.Node, path string, requestBody []byte, envelope, idempotency string) (*http.Response, error) {
	token, err := security.Decrypt(s.config.EncryptionKey, node.TokenEncrypted)
	if err != nil {
		return nil, errSignedJobRegistrationUnavailable
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, node.Endpoint+path, bytes.NewReader(requestBody))
	if err != nil {
		return nil, errSignedJobRegistrationUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Correlation-ID", r.Header.Get("X-Correlation-ID"))
	if envelope != "" {
		request.Header.Set(signedAuthorizationHeader, envelope)
	}
	if idempotency != "" {
		request.Header.Set("Idempotency-Key", idempotency)
	}
	return s.client.Do(request)
}

func signedCopyResponseBody(response *http.Response, header string) ([]byte, error) {
	if response == nil {
		return nil, errSignedJobRegistrationUnavailable
	}
	defer response.Body.Close()
	if len(response.Header.Values(header)) != 1 || response.Header.Get(header) != "v1" {
		return nil, errSignedJobRegistrationUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || filetypes.ValidateUniqueJSON(body) != nil {
		return nil, errSignedJobRegistrationUnavailable
	}
	return body, nil
}

func (s *Server) prepareSignedCopy(r *http.Request, node store.Node, input store.SignedCopyRequest, body []byte) (signedauth.JobOptions, error) {
	var info struct {
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := s.callNodeJSON(r.Context(), node, http.MethodGet, "/api/v1/node", nil, &info, r.Header.Get("X-Correlation-ID")); err != nil || info.NodeID != node.ID || !supportsSignedJobRegistration(info.Capabilities) {
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	creation, status := false, false
	for _, capability := range info.Capabilities {
		creation = creation || capability == "signed_local_copy_creation_v1"
		status = status || capability == "signed_job_authorization_status_v1"
	}
	if !creation || !status {
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	response, err := s.signedCopyNodeRequest(r, node, "/api/v1/jobs/signed-local-copy/prepare", body, "", "")
	if err != nil {
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	data, err := signedCopyResponseBody(response, "X-Jolt-Signed-Job-Preparation")
	if err != nil {
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	var result struct {
		Options          json.RawMessage `json:"options"`
		Digest           *string         `json:"options_digest"`
		ExecutionEnabled *bool           `json:"execution_enabled"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Digest == nil || result.ExecutionEnabled == nil || *result.ExecutionEnabled {
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	var fields map[string]json.RawMessage
	var options signedauth.JobOptions
	optionDecoder := json.NewDecoder(bytes.NewReader(result.Options))
	optionDecoder.DisallowUnknownFields()
	if json.Unmarshal(result.Options, &fields) != nil || len(fields) != 9 || optionDecoder.Decode(&options) != nil || optionDecoder.Decode(new(any)) != io.EOF || *result.Digest != signedauth.JobOptionsDigest(options) || !input.MatchesOptions(options) || r.Context().Err() != nil {
		return signedauth.JobOptions{}, errSignedJobRegistrationUnavailable
	}
	return options, nil
}

// createSignedLocalCopy is internal until renewable execution and routing are
// integrated. The intent is committed before the node sees the creation call.
func (s *Server) createSignedLocalCopy(r *http.Request, nodeID, idempotency string, input store.SignedCopyRequest) (string, error) {
	fail := func() (string, error) { return "", errSignedJobRegistrationUnavailable }
	if !validPathIdentifier(nodeID) || !signedauth.ValidKeyID(idempotency) || len(s.config.AuthorizationSigningKey) != ed25519.PrivateKeySize {
		return fail()
	}
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		return fail()
	}
	actor, actorType := currentUser(r), currentActorType(r)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	if !actor.Enabled || actor.ID == "" || credential == "" || digest == "" {
		return fail()
	}
	keys := map[string]ed25519.PublicKey{s.config.AuthorizationSigningKeyID: s.config.AuthorizationSigningKey.Public().(ed25519.PublicKey)}
	now := time.Now().UTC()
	intent, err := s.store.LoadSignedCopyIntent(r.Context(), nodeID, actorType, actor.ID, credential, digest, idempotency, keys, now)
	if errors.Is(err, store.ErrNotFound) {
		body, marshalErr := json.Marshal(input)
		if marshalErr != nil {
			return fail()
		}
		options, prepareErr := s.prepareSignedCopy(r, node, input, body)
		if prepareErr != nil {
			return fail()
		}
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return fail()
		}
		job := copyIntentJob("job-"+hex.EncodeToString(random[:]), input, options)
		now = time.Now().UTC()
		envelope, issueErr := s.issueSignedLocalJobLease(r, nodeID, job, 1, now)
		if issueErr != nil {
			return fail()
		}
		binding, verifyErr := signedauth.VerifiedJobLeaseBinding(envelope, keys, nodeID, now)
		if verifyErr != nil {
			return fail()
		}
		link := store.JobAuthorizationLink{NodeID: nodeID, JobID: job.ID, ActorType: actorType, ActorID: actor.ID, CredentialID: credential, CredentialDigest: digest, Binding: binding}
		intent, _, err = s.store.CreateSignedCopyIntent(r.Context(), link, idempotency, body, options, envelope, keys, now)
	}
	if err != nil || intent.Request != input {
		return fail()
	}
	job := copyIntentJob(intent.Link.JobID, intent.Request, intent.Options)
	now = time.Now().UTC()
	fresh, err := s.issueSignedLocalJobLease(r, nodeID, job, 1, now)
	if err != nil {
		return fail()
	}
	freshClaims, _, err := signedauth.VerifyJobLease(fresh, keys, intent.Link.Binding, nodeID, 1, now)
	if err != nil {
		return fail()
	}
	if intent.Accepted {
		return intent.Link.JobID, nil
	}
	if !intent.Expiry.After(now) {
		intent, err = s.store.RefreshSignedCopyIntent(r.Context(), nodeID, actorType, actor.ID, credential, digest, idempotency, fresh, keys, now)
		if err != nil {
			return fail()
		}
	} else {
		pending, _, verifyErr := signedauth.VerifyJobLease(intent.Envelope, keys, intent.Link.Binding, nodeID, 1, now)
		if verifyErr != nil || freshClaims.ExpiresAt < pending.ExpiresAt || !bytes.Equal(freshClaims.Context, pending.Context) {
			return fail()
		}
	}
	body, err := json.Marshal(intent.Request)
	if err != nil || !intent.Expiry.After(time.Now().UTC()) {
		return fail()
	}
	currentOptions, err := s.prepareSignedCopy(r, node, intent.Request, body)
	if err != nil || currentOptions != intent.Options || !intent.Expiry.After(time.Now().UTC()) {
		return fail()
	}
	response, err := s.signedCopyNodeRequest(r, node, "/api/v1/jobs/signed-local-copy", body, intent.Envelope, idempotency)
	if err != nil {
		return fail()
	}
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK {
		response.Body.Close()
		return fail()
	}
	data, err := signedCopyResponseBody(response, "X-Jolt-Signed-Job-Creation")
	if err != nil {
		return fail()
	}
	var result struct {
		Job              json.RawMessage `json:"job"`
		ExecutionEnabled *bool           `json:"execution_enabled"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.ExecutionEnabled == nil || *result.ExecutionEnabled {
		return fail()
	}
	var nodeJob signedLocalJob
	if json.Unmarshal(result.Job, &nodeJob) != nil || r.Context().Err() != nil {
		return fail()
	}
	receipt := store.SignedCopyReceipt{JobID: nodeJob.ID, Type: nodeJob.Type, State: nodeJob.State, MountID: nodeJob.MountID, Source: nodeJob.Source, Destination: nodeJob.Destination, Options: signedauth.JobOptions{Overwrite: nodeJob.Overwrite, Recursive: nodeJob.Recursive, ConflictPolicy: nodeJob.ConflictPolicy, SourceChangePolicy: nodeJob.SourceChangePolicy, VerifyChecksum: nodeJob.VerifyChecksum, BandwidthLimit: nodeJob.BandwidthLimit, MaxParallelFiles: nodeJob.MaxParallelFiles, MaxParallelChunks: nodeJob.MaxParallelChunks, MaxAttempts: nodeJob.MaxAttempts}}
	if err := s.store.CompleteSignedCopyIntent(r.Context(), nodeID, actorType, actor.ID, credential, digest, idempotency, receipt, keys, time.Now().UTC()); err != nil {
		return fail()
	}
	return intent.Link.JobID, nil
}

package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// signedTransferJobID derives the job identifier from the actor and the
// client's idempotency key, so a retried request finds the same job on the node
// without the Control Tower keeping any extra state.
func signedTransferJobID(actorType, actorID, idempotency, destinationNodeID string) string {
	sum := sha256.Sum256([]byte("jolt-signed-transfer-job-v1\x00" + actorType + "\x00" + actorID + "\x00" + destinationNodeID + "\x00" + idempotency))
	return "xfer-" + hex.EncodeToString(sum[:16])
}

func (s *Server) cancelNodeJob(r *http.Request, node store.Node, jobID string) {
	if response, err := s.signedCopyNodeRequest(r, node, "/api/v1/jobs/"+url.PathEscape(jobID)+"/cancel", nil, "", ""); err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
}

// createSignedLogicalTransfer creates a node-to-node copy as a job bound to the
// caller's authorization. The destination node plans it under the signed
// policy, so entries the caller may not read are never planned, and keeps it
// authorized only while this server renews its lease. Moves are not handled
// here; they delete the source and have no plan yet.
func (s *Server) createSignedLogicalTransfer(w http.ResponseWriter, r *http.Request, resolved resolvedLogicalTransfer) {
	destination, source := resolved.DestinationNode, resolved.SourceNode
	// The signed policy names nodes by their registered IDs, so those must be
	// the identities the nodes report; otherwise the rules would not match.
	if resolved.SourcePeerNodeID != source.ID {
		writeError(w, r, http.StatusConflict, "node_identity_mismatch", "O node de origem usa uma identidade diferente da registrada; atualize o cadastro antes de transferir.")
		return
	}
	if !s.nodeHasCapabilities(r, destination, "signed_transfer_pull_v1", "signed_local_copy_execution_v1", "signed_job_authorization_registration_v1", "signed_job_options_binding_v1", "signed_job_authorization_status_v1") {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node de destino para usar transferências com autorização renovável.")
		return
	}
	actor, actorType := currentUser(r), currentActorType(r)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !actor.Enabled || actor.ID == "" || credential == "" || digest == "" || idempotency == "" || len(s.config.AuthorizationSigningKey) != ed25519.PrivateKeySize {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_unavailable", "Não foi possível autorizar a transferência.")
		return
	}
	fail := func() {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_unavailable", "Não foi possível criar a transferência protegida. Verifique a versão dos nodes e as permissões atuais.")
	}
	payload := resolved.nodeRequest(r.Header.Get("X-Correlation-ID"))
	encoded, err := json.Marshal(payload)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var prepared struct {
		Options          json.RawMessage `json:"options"`
		Digest           *string         `json:"options_digest"`
		ExecutionEnabled *bool           `json:"execution_enabled"`
	}
	if err := s.callNodeJSON(r.Context(), destination, http.MethodPost, "/api/v1/transfers/signed-pull/batch/prepare", payload, &prepared, r.Header.Get("X-Correlation-ID")); err != nil {
		if !nodeAPIErrorResponse(w, r, err) {
			fail()
		}
		return
	}
	var fields map[string]json.RawMessage
	var options signedauth.JobOptions
	optionDecoder := json.NewDecoder(bytes.NewReader(prepared.Options))
	optionDecoder.DisallowUnknownFields()
	if prepared.Digest == nil || prepared.ExecutionEnabled == nil || !*prepared.ExecutionEnabled || json.Unmarshal(prepared.Options, &fields) != nil || len(fields) != 9 ||
		optionDecoder.Decode(&options) != nil || optionDecoder.Decode(new(any)) != io.EOF || *prepared.Digest != signedauth.JobOptionsDigest(options) {
		fail()
		return
	}
	scope := transferScope{
		SourceNodeID: source.ID, SourceMountID: resolved.Request.Source.MountID, SourceGrantRoot: rootPath(resolved.SourceGrant.Path),
		SourcePaths: resolved.Request.Source.Paths, DestinationPath: rootPath(resolved.Request.Destination.Path),
		MayOverwrite: transferMayOverwrite(resolved.Request.ConflictPolicy),
	}
	jobID := signedTransferJobID(actorType, actor.ID, idempotency, destination.ID)
	job := signedLocalJob{
		ID: jobID, Type: "transfer_pull_batch", MountID: resolved.DestinationGrant.MountID, Source: scope.SourceGrantRoot, Destination: scope.DestinationPath,
		Overwrite: options.Overwrite, Recursive: options.Recursive, ConflictPolicy: options.ConflictPolicy, SourceChangePolicy: options.SourceChangePolicy,
		VerifyChecksum: options.VerifyChecksum, BandwidthLimit: options.BandwidthLimit, MaxParallelFiles: options.MaxParallelFiles,
		MaxParallelChunks: options.MaxParallelChunks, MaxAttempts: options.MaxAttempts,
		PeerNodeID: resolved.SourcePeerNodeID, SourceGrantID: resolved.SourceGrant.ID, DestinationGrantID: resolved.DestinationGrant.ID,
	}
	now := time.Now().UTC()
	envelope, err := s.issueSignedTransferLeaseFor(r, destination.ID, job, scope, 1, now)
	if err != nil {
		// The caller lacks a permission the lease needs; nothing was created.
		s.audit(r, "execute", "nodes/"+destination.ID+"/transfers", "denied")
		writeError(w, r, http.StatusForbidden, "permission_denied", "A policy atual não permite esta transferência.")
		return
	}
	keys := map[string]ed25519.PublicKey{s.config.AuthorizationSigningKeyID: s.config.AuthorizationSigningKey.Public().(ed25519.PublicKey)}
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, destination.ID, now)
	if err != nil || binding.JobOptionsDigest != *prepared.Digest {
		fail()
		return
	}
	response, err := s.signedCopyNodeRequest(r, destination, "/api/v1/transfers/signed-pull/batch", encoded, envelope, jobID)
	if err != nil {
		fail()
		return
	}
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		data, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		response.Body.Close()
		if json.Unmarshal(data, &failure) == nil && failure.Error.Code != "" && response.StatusCode >= 400 && response.StatusCode <= 599 {
			writeError(w, r, response.StatusCode, failure.Error.Code, failure.Error.Message)
			return
		}
		fail()
		return
	}
	data, err := signedCopyResponseBody(response, "X-Jolt-Signed-Transfer-Creation")
	var created struct {
		Job              signedLocalJob `json:"job"`
		ExecutionEnabled *bool          `json:"execution_enabled"`
	}
	if err != nil || json.Unmarshal(data, &created) != nil || created.Job.ID != jobID || created.Job.Type != "transfer_pull_batch" || created.ExecutionEnabled == nil || !*created.ExecutionEnabled {
		fail()
		return
	}
	abort := func() {
		s.cancelNodeJob(r, destination, jobID)
		fail()
	}
	link := store.JobAuthorizationLink{NodeID: destination.ID, JobID: jobID, ActorType: actorType, ActorID: actor.ID, CredentialID: credential, CredentialDigest: digest, Binding: binding}
	if err := s.store.CreateJobAuthorizationLink(r.Context(), link, time.Now().UTC()); err != nil {
		existing, getErr := s.store.GetJobAuthorizationLink(r.Context(), destination.ID, jobID)
		if getErr != nil || existing.ActorID != actor.ID || existing.CredentialDigest != digest {
			abort()
			return
		}
	}
	scopeJSON, err := json.Marshal(scope)
	if err != nil || s.store.SaveJobAuthorizationScope(r.Context(), destination.ID, jobID, scopeJSON, time.Now().UTC()) != nil {
		abort()
		return
	}
	s.audit(r, "execute", "nodes/"+destination.ID+"/transfers", "allowed")
	// Deliver the first lease now instead of waiting for the renewal loop. A
	// failure here is harmless: the loop retries it within seconds.
	_, _ = s.renewSignedLocalJobLease(r.Context(), destination.ID, jobID)
	var current json.RawMessage
	if err := s.callNodeJSON(r.Context(), destination, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &current, r.Header.Get("X-Correlation-ID")); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "A transferência foi criada, mas o estado do job não pôde ser lido.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/api/v1/nodes/"+url.PathEscape(destination.ID)+"/jobs/"+url.PathEscape(jobID))
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write(current)
}

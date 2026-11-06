package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

// signedTransfer is a node-to-node copy prepared for the destination node: the
// normalized options, the scope the caller is authorized for and a first lease.
type signedTransfer struct {
	destination, source store.Node
	encoded             []byte
	options             signedauth.JobOptions
	optionsDigest       string
	scope               transferScope
	jobID               string
	envelope            string
	jobType             string
	binding             signedauth.Binding
	actor               store.User
	actorType           string
	credential          string
	credentialDigest    string
}

// prepareSignedTransfer checks the nodes can run a signed copy, asks the
// destination to normalize the options and issues the lease. preview selects a
// throwaway job id for a preview, which never becomes a job. It answers the
// request itself and returns false when the copy cannot be prepared.
func (s *Server) prepareSignedTransfer(w http.ResponseWriter, r *http.Request, resolved resolvedLogicalTransfer, preview bool) (signedTransfer, bool) {
	destination, source := resolved.DestinationNode, resolved.SourceNode
	// The signed policy names nodes by their registered IDs, so those must be
	// the identities the nodes report; otherwise the rules would not match.
	if resolved.SourcePeerNodeID != source.ID {
		writeError(w, r, http.StatusConflict, "node_identity_mismatch", "O node de origem usa uma identidade diferente da registrada; atualize o cadastro antes de transferir.")
		return signedTransfer{}, false
	}
	if !s.nodeHasCapabilities(r, destination, "signed_transfer_pull_v1", "signed_local_copy_execution_v1", "signed_job_authorization_registration_v1", "signed_job_options_binding_v1", "signed_job_authorization_status_v1") {
		writeError(w, r, http.StatusConflict, "node_upgrade_required", "Atualize o node de destino para usar transferências com autorização renovável.")
		return signedTransfer{}, false
	}
	actor, actorType := currentUser(r), currentActorType(r)
	credential, _ := r.Context().Value(credentialKey).(string)
	digest, _ := r.Context().Value(credentialDigestKey).(string)
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if !actor.Enabled || actor.ID == "" || credential == "" || digest == "" || (!preview && idempotency == "") || len(s.signingKey()) != ed25519.PrivateKeySize {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_unavailable", "Não foi possível autorizar a transferência.")
		return signedTransfer{}, false
	}
	fail := func() (signedTransfer, bool) {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_unavailable", "Não foi possível preparar a transferência protegida. Verifique a versão dos nodes e as permissões atuais.")
		return signedTransfer{}, false
	}
	moving := resolved.Request.Operation == "move"
	if moving && !preview && (resolved.Request.MovePlan == nil || resolved.Request.MovePlan.ID == "" || resolved.Request.MovePlan.Token == "") {
		writeError(w, r, http.StatusUnprocessableEntity, "plan_required", "Mover exige a prévia e a confirmação do plano. Gere a prévia e confirme com o token recebido.")
		return signedTransfer{}, false
	}
	payload := resolved.nodeRequest(r.Header.Get("X-Correlation-ID"))
	if moving {
		// The node trusts the subject because this server authenticated it.
		payload["subject_type"] = actorType
		if !preview {
			payload["plan_id"], payload["plan_token"] = resolved.Request.MovePlan.ID, resolved.Request.MovePlan.Token
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		s.fail(w, r, err)
		return signedTransfer{}, false
	}
	var prepared struct {
		Options          json.RawMessage `json:"options"`
		Digest           *string         `json:"options_digest"`
		ExecutionEnabled *bool           `json:"execution_enabled"`
	}
	if err := s.callNodeJSON(r.Context(), destination, http.MethodPost, "/api/v1/transfers/signed-pull/batch/prepare", payload, &prepared, r.Header.Get("X-Correlation-ID")); err != nil {
		if !nodeAPIErrorResponse(w, r, err) {
			return fail()
		}
		return signedTransfer{}, false
	}
	var fields map[string]json.RawMessage
	var options signedauth.JobOptions
	optionDecoder := json.NewDecoder(bytes.NewReader(prepared.Options))
	optionDecoder.DisallowUnknownFields()
	if prepared.Digest == nil || prepared.ExecutionEnabled == nil || !*prepared.ExecutionEnabled || json.Unmarshal(prepared.Options, &fields) != nil || len(fields) != 9 ||
		optionDecoder.Decode(&options) != nil || optionDecoder.Decode(new(any)) != io.EOF || *prepared.Digest != signedauth.JobOptionsDigest(options) {
		return fail()
	}
	scope := transferScope{
		SourceNodeID: source.ID, SourceMountID: resolved.Request.Source.MountID, SourceGrantRoot: rootPath(resolved.SourceGrant.Path),
		SourcePaths: resolved.Request.Source.Paths, DestinationPath: rootPath(resolved.Request.Destination.Path),
		MayOverwrite: transferMayOverwrite(resolved.Request.ConflictPolicy), Operation: resolved.Request.Operation,
	}
	jobType := "transfer_pull_batch"
	if moving {
		jobType = "transfer_move_batch"
	}
	jobID := signedTransferJobID(actorType, actor.ID, idempotency, destination.ID)
	if preview {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return fail()
		}
		jobID = "preview-" + hex.EncodeToString(random[:])
	}
	job := signedLocalJob{
		ID: jobID, Type: jobType, MountID: resolved.DestinationGrant.MountID, Source: scope.SourceGrantRoot, Destination: scope.DestinationPath,
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
		return signedTransfer{}, false
	}
	keys := s.verificationKeys()
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, keys, destination.ID, now)
	if err != nil || binding.JobOptionsDigest != *prepared.Digest {
		return fail()
	}
	return signedTransfer{destination: destination, source: source, encoded: encoded, options: options, optionsDigest: *prepared.Digest, scope: scope, jobID: jobID,
		envelope: envelope, jobType: jobType, binding: binding, actor: actor, actorType: actorType, credential: credential, credentialDigest: digest}, true
}

// planSignedLogicalTransfer previews a node-to-node copy under the caller's
// own policy: the destination node plans it with a throwaway lease, so entries
// the policy hides are not listed, only counted.
func (s *Server) planSignedLogicalTransfer(w http.ResponseWriter, r *http.Request, resolved resolvedLogicalTransfer) {
	transfer, ok := s.prepareSignedTransfer(w, r, resolved, true)
	if !ok {
		return
	}
	response, err := s.signedCopyNodeRequest(r, transfer.destination, "/api/v1/transfers/signed-pull/batch/plan", transfer.encoded, transfer.envelope, "")
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "O node de destino está indisponível.")
		return
	}
	if response.StatusCode != http.StatusOK {
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
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node de destino.")
		return
	}
	data, err := signedCopyResponseBody(response, "X-Jolt-Signed-Transfer-Plan")
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_unavailable", "Resposta inválida do node de destino.")
		return
	}
	s.audit(r, "plan", "nodes/"+transfer.destination.ID+"/transfers", "allowed")
	writeJSON(w, http.StatusOK, map[string]any{"plan": json.RawMessage(data), "max_source_paths": s.transferMaxSourcePaths()})
}

// createSignedLogicalTransfer creates a node-to-node copy as a job bound to the
// caller's authorization. The destination node plans it under the signed
// policy, so entries the caller may not read are never planned, and keeps it
// authorized only while this server renews its lease. Moves are not handled
// here; they delete the source and have no plan yet.
func (s *Server) createSignedLogicalTransfer(w http.ResponseWriter, r *http.Request, resolved resolvedLogicalTransfer) {
	transfer, ok := s.prepareSignedTransfer(w, r, resolved, false)
	if !ok {
		return
	}
	destination, jobID := transfer.destination, transfer.jobID
	fail := func() {
		writeError(w, r, http.StatusServiceUnavailable, "signed_job_unavailable", "Não foi possível criar a transferência protegida. Verifique a versão dos nodes e as permissões atuais.")
	}
	response, err := s.signedCopyNodeRequest(r, destination, "/api/v1/transfers/signed-pull/batch", transfer.encoded, transfer.envelope, jobID)
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
	if err != nil || json.Unmarshal(data, &created) != nil || created.Job.ID != jobID || created.Job.Type != transfer.jobType || created.ExecutionEnabled == nil || !*created.ExecutionEnabled {
		fail()
		return
	}
	abort := func() {
		s.cancelNodeJob(r, destination, jobID)
		fail()
	}
	link := store.JobAuthorizationLink{NodeID: destination.ID, JobID: jobID, ActorType: transfer.actorType, ActorID: transfer.actor.ID, CredentialID: transfer.credential, CredentialDigest: transfer.credentialDigest, Binding: transfer.binding}
	if err := s.store.CreateJobAuthorizationLink(r.Context(), link, time.Now().UTC()); err != nil {
		existing, getErr := s.store.GetJobAuthorizationLink(r.Context(), destination.ID, jobID)
		if getErr != nil || existing.ActorID != transfer.actor.ID || existing.CredentialDigest != transfer.credentialDigest {
			abort()
			return
		}
	}
	scopeJSON, err := json.Marshal(transfer.scope)
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

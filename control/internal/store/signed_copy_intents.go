package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

// SignedCopyRequest matches the node's operational copy creation contract.
type SignedCopyRequest struct {
	MountID            string `json:"mount_id"`
	Source             string `json:"source_path"`
	Destination        string `json:"destination_path"`
	Overwrite          bool   `json:"overwrite"`
	Recursive          bool   `json:"recursive"`
	ConflictPolicy     string `json:"conflict_policy"`
	SourceChangePolicy string `json:"source_change_policy"`
	VerifyChecksum     bool   `json:"verify_checksum"`
	BandwidthLimit     int64  `json:"bandwidth_limit_bytes_per_second"`
	MaxParallelFiles   int    `json:"max_parallel_files"`
	MaxParallelChunks  int    `json:"max_parallel_chunks"`
	MaxAttempts        int    `json:"max_attempts"`
}

// SignedCopyIntent is private encrypted state and must never be returned as JSON.
type SignedCopyIntent struct {
	Link           JobAuthorizationLink  `json:"-"`
	IdempotencyKey string                `json:"-"`
	Request        SignedCopyRequest     `json:"-"`
	Options        signedauth.JobOptions `json:"-"`
	Envelope       string                `json:"-"`
	Expiry         time.Time             `json:"-"`
	Accepted       bool                  `json:"-"`
}

func (request SignedCopyRequest) matchesOptions(options signedauth.JobOptions) bool {
	conflict := strings.ToLower(strings.TrimSpace(request.ConflictPolicy))
	if conflict == "" {
		if request.Overwrite {
			conflict = "overwrite"
		} else {
			conflict = "fail"
		}
	}
	switch conflict {
	case "skip", "overwrite", "rename", "fail", "ask", "checksum":
	default:
		return false
	}
	change := strings.ToLower(strings.TrimSpace(request.SourceChangePolicy))
	if change == "" {
		change = "fail"
	}
	switch change {
	case "fail", "retry", "copy_anyway":
	default:
		return false
	}
	return request.Overwrite == options.Overwrite && request.Recursive == options.Recursive && conflict == options.ConflictPolicy && change == options.SourceChangePolicy && (request.VerifyChecksum || conflict == "checksum") == options.VerifyChecksum && request.BandwidthLimit >= 0 && request.BandwidthLimit <= 1<<40 && request.BandwidthLimit == options.BandwidthLimit && request.MaxParallelFiles >= 0 && request.MaxParallelFiles <= 32 && options.MaxParallelFiles > 0 && options.MaxParallelFiles <= 32 && (request.MaxParallelFiles == 0 || request.MaxParallelFiles == options.MaxParallelFiles) && request.MaxParallelChunks >= 0 && request.MaxParallelChunks <= 16 && options.MaxParallelChunks > 0 && options.MaxParallelChunks <= 16 && (request.MaxParallelChunks == 0 || request.MaxParallelChunks == options.MaxParallelChunks) && options.MaxAttempts > 0 && (request.MaxAttempts <= 0 || request.MaxAttempts == options.MaxAttempts)
}

func strictIntentJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 64*1024 || filetypes.ValidateUniqueJSON(raw) != nil {
		return ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrConflict
	}
	return nil
}

// CreateSignedCopyIntent persists a signed creation intent before contacting
// the node. Callers must freshly authorize the actor, retrieve the registered
// node's normalized options and recheck policies before every delivery.
func (s *Store) CreateSignedCopyIntent(ctx context.Context, link JobAuthorizationLink, idempotencyKey string, requestJSON []byte, options signedauth.JobOptions, envelope string, keys map[string]ed25519.PublicKey, now time.Time) (SignedCopyIntent, bool, error) {
	fail := func() (SignedCopyIntent, bool, error) { return SignedCopyIntent{}, false, ErrConflict }
	if !signedauth.ValidKeyID(link.NodeID) || !signedauth.ValidKeyID(link.JobID) || !signedauth.ValidKeyID(link.ActorID) || !signedauth.ValidKeyID(link.CredentialID) || !signedauth.ValidKeyID(idempotencyKey) || !validCredentialDigest(link.CredentialDigest) || now.IsZero() || link.Binding.Operation != "copy_local" || link.Binding.ActorID != link.ActorID || link.Binding.CredentialID != link.CredentialID || link.Binding.PlanID != link.JobID || link.Binding.SourceNodeID != link.NodeID || link.Binding.DestinationNodeID != link.NodeID || link.Binding.RequestID != "" || link.Binding.JobOptionsDigest == "" || link.Binding.JobOptionsDigest != signedauth.JobOptionsDigest(options) || link.ConfirmedRevision != 0 || link.ConfirmedDigest != "" || !link.ConfirmedExpiry.IsZero() || link.PendingRevision != 0 || link.PendingEnvelope != "" || !link.PendingExpiry.IsZero() {
		return fail()
	}
	var request SignedCopyRequest
	if strictIntentJSON(requestJSON, &request) != nil || request.MountID != link.Binding.SourceMountID || request.MountID != link.Binding.DestinationMountID || request.Source != link.Binding.SourceRoot || request.Destination != link.Binding.DestinationRoot || !request.matchesOptions(options) {
		return fail()
	}
	claims, _, err := signedauth.VerifyJobLease(envelope, keys, link.Binding, link.NodeID, 1, now)
	if err != nil {
		return fail()
	}
	expiry := time.Unix(claims.ExpiresAt, 0).UTC()
	boundJSON, err := json.Marshal(link.Binding)
	if err != nil {
		return fail()
	}
	requestBody, err := json.Marshal(request)
	if err != nil {
		return fail()
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return fail()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SignedCopyIntent{}, false, err
	}
	defer tx.Rollback()
	credentialExpiry, err := currentLinkedCredentialTx(ctx, tx, link, now)
	if err != nil {
		return SignedCopyIntent{}, false, err
	}
	if credentialExpiry != nil && expiry.After(*credentialExpiry) {
		return fail()
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id=?`, link.NodeID).Scan(&exists); err != nil {
		return SignedCopyIntent{}, false, err
	}
	if exists != 1 {
		return SignedCopyIntent{}, false, ErrNotFound
	}
	var jobID, oldCredential, oldDigest, oldBinding, oldRequest, oldOptions, oldEnvelope string
	var oldExpiry, accepted int64
	err = tx.QueryRowContext(ctx, `SELECT job_id,credential_id,credential_digest,binding,request_body,options,envelope,expiry_ns,accepted FROM signed_copy_intents WHERE node_id=? AND actor_type=? AND actor_id=? AND idempotency_key=?`, link.NodeID, link.ActorType, link.ActorID, idempotencyKey).Scan(&jobID, &oldCredential, &oldDigest, &oldBinding, &oldRequest, &oldOptions, &oldEnvelope, &oldExpiry, &accepted)
	if err == nil {
		var previous signedauth.Binding
		if strictIntentJSON([]byte(oldBinding), &previous) != nil || oldCredential != link.CredentialID || oldDigest != link.CredentialDigest || oldRequest != string(requestBody) || oldOptions != string(optionsJSON) || (accepted != 0 && accepted != 1) || oldExpiry <= 0 || oldExpiry%int64(time.Second) != 0 || oldEnvelope == "" {
			return fail()
		}
		current := link.Binding
		current.PlanID = previous.PlanID
		if current != previous || previous.PlanID != jobID {
			return fail()
		}
		oldTime := time.Unix(0, oldExpiry).UTC()
		oldClaims, _, verifyErr := signedauth.VerifyJobLease(oldEnvelope, keys, previous, link.NodeID, 1, oldTime.Add(-time.Second))
		if verifyErr != nil || oldClaims.ExpiresAt != oldTime.Unix() {
			return fail()
		}
		link.JobID, link.Binding = jobID, previous
		return SignedCopyIntent{Link: link, IdempotencyKey: idempotencyKey, Request: request, Options: options, Envelope: oldEnvelope, Expiry: oldTime, Accepted: accepted == 1}, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SignedCopyIntent{}, false, err
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO signed_copy_intents(node_id,job_id,actor_type,actor_id,credential_id,credential_digest,idempotency_key,binding,request_body,options,envelope,expiry_ns,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, link.NodeID, link.JobID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, idempotencyKey, string(boundJSON), string(requestBody), string(optionsJSON), envelope, expiry.UnixNano(), stamp, stamp)
	if isUniqueConstraint(err) {
		return fail()
	}
	if err != nil {
		return SignedCopyIntent{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','7') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<7 THEN '7' ELSE value END`); err != nil {
		return SignedCopyIntent{}, false, err
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: link.ActorID, actorType: link.ActorType, action: "prepare_signed_copy", resource: "nodes/" + link.NodeID + "/jobs/" + link.JobID, result: "allowed", createdAt: stamp}); err != nil {
		return SignedCopyIntent{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return SignedCopyIntent{}, false, err
	}
	return SignedCopyIntent{Link: link, IdempotencyKey: idempotencyKey, Request: request, Options: options, Envelope: envelope, Expiry: expiry}, false, nil
}

// LoadSignedCopyIntent recovers a previously persisted intent, even if its
// envelope has expired. Expired envelopes cannot be delivered; callers must
// re-evaluate permissions and obtain a fresh one before contacting the node.
func (s *Store) LoadSignedCopyIntent(ctx context.Context, nodeID, actorType, actorID, credentialID, credentialDigest, idempotencyKey string, keys map[string]ed25519.PublicKey, now time.Time) (SignedCopyIntent, error) {
	fail := func() (SignedCopyIntent, error) { return SignedCopyIntent{}, ErrConflict }
	if !signedauth.ValidKeyID(nodeID) || !signedauth.ValidKeyID(actorID) || !signedauth.ValidKeyID(credentialID) || !signedauth.ValidKeyID(idempotencyKey) || !validCredentialDigest(credentialDigest) || now.IsZero() {
		return fail()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SignedCopyIntent{}, err
	}
	defer tx.Rollback()
	var jobID, storedCredential, storedDigest, rawBinding, rawRequest, rawOptions, envelope string
	var expiryNS, accepted int64
	err = tx.QueryRowContext(ctx, `SELECT job_id,credential_id,credential_digest,binding,request_body,options,envelope,expiry_ns,accepted FROM signed_copy_intents WHERE node_id=? AND actor_type=? AND actor_id=? AND idempotency_key=?`, nodeID, actorType, actorID, idempotencyKey).Scan(&jobID, &storedCredential, &storedDigest, &rawBinding, &rawRequest, &rawOptions, &envelope, &expiryNS, &accepted)
	if errors.Is(err, sql.ErrNoRows) {
		return SignedCopyIntent{}, ErrNotFound
	}
	if err != nil {
		return SignedCopyIntent{}, err
	}
	if storedCredential != credentialID || storedDigest != credentialDigest || !signedauth.ValidKeyID(jobID) || expiryNS <= 0 || expiryNS%int64(time.Second) != 0 || (accepted != 0 && accepted != 1) {
		return fail()
	}
	var binding signedauth.Binding
	var request SignedCopyRequest
	var options signedauth.JobOptions
	if strictIntentJSON([]byte(rawBinding), &binding) != nil || strictIntentJSON([]byte(rawRequest), &request) != nil || strictIntentJSON([]byte(rawOptions), &options) != nil || binding.ActorID != actorID || binding.CredentialID != credentialID || binding.SourceNodeID != nodeID || binding.DestinationNodeID != nodeID || binding.PlanID != jobID || binding.Operation != "copy_local" || binding.RequestID != "" || binding.JobOptionsDigest == "" || binding.JobOptionsDigest != signedauth.JobOptionsDigest(options) || request.MountID != binding.SourceMountID || request.MountID != binding.DestinationMountID || request.Source != binding.SourceRoot || request.Destination != binding.DestinationRoot || !request.matchesOptions(options) {
		return fail()
	}
	expiry := time.Unix(0, expiryNS).UTC()
	claims, _, err := signedauth.VerifyJobLease(envelope, keys, binding, nodeID, 1, expiry.Add(-time.Second))
	if err != nil || claims.ExpiresAt != expiry.Unix() {
		return fail()
	}
	link := JobAuthorizationLink{NodeID: nodeID, JobID: jobID, ActorType: actorType, ActorID: actorID, CredentialID: credentialID, CredentialDigest: credentialDigest, Binding: binding}
	if _, err := currentLinkedCredentialTx(ctx, tx, link, now); err != nil {
		return SignedCopyIntent{}, err
	}
	return SignedCopyIntent{Link: link, IdempotencyKey: idempotencyKey, Request: request, Options: options, Envelope: envelope, Expiry: expiry, Accepted: accepted == 1}, nil
}

// RefreshSignedCopyIntent replaces an expired envelope only after the caller
// has freshly re-evaluated all policies and prepared the same signed scope.
// No node request or job execution is performed by this transaction.
func (s *Store) RefreshSignedCopyIntent(ctx context.Context, nodeID, actorType, actorID, credentialID, credentialDigest, idempotencyKey, envelope string, keys map[string]ed25519.PublicKey, now time.Time) (SignedCopyIntent, error) {
	intent, err := s.LoadSignedCopyIntent(ctx, nodeID, actorType, actorID, credentialID, credentialDigest, idempotencyKey, keys, now)
	if err != nil {
		return SignedCopyIntent{}, err
	}
	if intent.Accepted || intent.Expiry.After(now) {
		return SignedCopyIntent{}, ErrConflict
	}
	claims, _, err := signedauth.VerifyJobLease(envelope, keys, intent.Link.Binding, nodeID, 1, now)
	if err != nil {
		return SignedCopyIntent{}, ErrConflict
	}
	expiry := time.Unix(claims.ExpiresAt, 0).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SignedCopyIntent{}, err
	}
	defer tx.Rollback()
	credentialExpiry, err := currentLinkedCredentialTx(ctx, tx, intent.Link, now)
	if err != nil {
		return SignedCopyIntent{}, err
	}
	if credentialExpiry != nil && expiry.After(*credentialExpiry) {
		return SignedCopyIntent{}, ErrConflict
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE signed_copy_intents SET envelope=?,expiry_ns=?,updated_at=? WHERE node_id=? AND job_id=? AND actor_type=? AND actor_id=? AND credential_id=? AND credential_digest=? AND idempotency_key=? AND accepted=0 AND envelope=? AND expiry_ns=?`, envelope, expiry.UnixNano(), stamp, nodeID, intent.Link.JobID, actorType, actorID, credentialID, credentialDigest, idempotencyKey, intent.Envelope, intent.Expiry.UnixNano())
	if err != nil {
		return SignedCopyIntent{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return SignedCopyIntent{}, ErrConflict
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: actorID, actorType: actorType, action: "refresh_signed_copy_intent", resource: "nodes/" + nodeID + "/jobs/" + intent.Link.JobID, result: "allowed", createdAt: stamp}); err != nil {
		return SignedCopyIntent{}, err
	}
	if err := tx.Commit(); err != nil {
		return SignedCopyIntent{}, err
	}
	intent.Envelope, intent.Expiry = envelope, expiry
	return intent, nil
}

// SignedCopyReceipt must be derived from an authenticated node response, not
// from the client or from the intent itself.
type SignedCopyReceipt struct {
	JobID, Type, State, MountID, Source, Destination string
	Options                                          signedauth.JobOptions
}

// CompleteSignedCopyIntent atomically records acceptance and the durable actor
// link after a caller validates the node response. It never enables execution.
func (s *Store) CompleteSignedCopyIntent(ctx context.Context, nodeID, actorType, actorID, credentialID, credentialDigest, idempotencyKey string, receipt SignedCopyReceipt, keys map[string]ed25519.PublicKey, now time.Time) error {
	intent, err := s.LoadSignedCopyIntent(ctx, nodeID, actorType, actorID, credentialID, credentialDigest, idempotencyKey, keys, now)
	if err != nil {
		return err
	}
	if receipt.JobID != intent.Link.JobID || receipt.Type != "copy_local" || receipt.State != "waiting_validation" || receipt.MountID != intent.Request.MountID || receipt.Source != intent.Request.Source || receipt.Destination != intent.Request.Destination || receipt.Options != intent.Options {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := currentLinkedCredentialTx(ctx, tx, intent.Link, now); err != nil {
		return err
	}
	var currentEnvelope string
	var expiryNS, accepted int64
	if err := tx.QueryRowContext(ctx, `SELECT envelope,expiry_ns,accepted FROM signed_copy_intents WHERE node_id=? AND job_id=? AND actor_type=? AND actor_id=? AND credential_id=? AND credential_digest=? AND idempotency_key=?`, nodeID, intent.Link.JobID, actorType, actorID, credentialID, credentialDigest, idempotencyKey).Scan(&currentEnvelope, &expiryNS, &accepted); err != nil {
		return err
	}
	if currentEnvelope != intent.Envelope || expiryNS != intent.Expiry.UnixNano() || (accepted != 0 && accepted != 1) {
		return ErrConflict
	}
	existing, err := readJobAuthorizationLink(tx.QueryRowContext(ctx, jobLinkSelect, nodeID, intent.Link.JobID))
	if err == nil {
		if existing.ActorType != actorType || existing.ActorID != actorID || existing.CredentialID != credentialID || existing.CredentialDigest != credentialDigest || existing.Binding != intent.Link.Binding {
			return ErrConflict
		}
	} else if errors.Is(err, ErrNotFound) && accepted == 0 {
		bindingJSON, err := json.Marshal(intent.Link.Binding)
		if err != nil {
			return err
		}
		stamp := now.UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_authorization_links(node_id,job_id,actor_type,actor_id,credential_id,credential_digest,binding,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, nodeID, intent.Link.JobID, actorType, actorID, credentialID, credentialDigest, string(bindingJSON), stamp, stamp); err != nil {
			return err
		}
	} else {
		return ErrConflict
	}
	if accepted == 1 {
		return nil
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE signed_copy_intents SET accepted=1,updated_at=? WHERE node_id=? AND job_id=? AND accepted=0 AND envelope=? AND expiry_ns=?`, stamp, nodeID, intent.Link.JobID, intent.Envelope, intent.Expiry.UnixNano())
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return ErrConflict
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: actorID, actorType: actorType, action: "accept_signed_copy", resource: "nodes/" + nodeID + "/jobs/" + intent.Link.JobID, result: "allowed", createdAt: stamp}); err != nil {
		return err
	}
	return tx.Commit()
}

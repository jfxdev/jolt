package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
)

// JobAuthorizationLink is private SQLCipher state, not a public API response.
// A caller must derive it from an authenticated subject and node-owned job.
type JobAuthorizationLink struct {
	NodeID            string             `json:"-"`
	JobID             string             `json:"-"`
	ActorType         string             `json:"-"`
	ActorID           string             `json:"-"`
	CredentialID      string             `json:"-"`
	CredentialDigest  string             `json:"-"`
	Binding           signedauth.Binding `json:"-"`
	ConfirmedRevision uint64             `json:"-"`
	ConfirmedDigest   string             `json:"-"`
	ConfirmedExpiry   time.Time          `json:"-"`
	PendingRevision   uint64             `json:"-"`
	PendingEnvelope   string             `json:"-"`
	PendingExpiry     time.Time          `json:"-"`
	CreatedAt         time.Time          `json:"-"`
	UpdatedAt         time.Time          `json:"-"`
}

func validCredentialDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

// currentLinkedCredentialTx checks the current subject and credential without
// trusting the persisted link alone. Federated automation is not enabled yet.
func currentLinkedCredentialTx(ctx context.Context, tx *sql.Tx, link JobAuthorizationLink, now time.Time) (*time.Time, error) {
	var expiry sql.NullString
	switch link.ActorType {
	case "user":
		if !strings.HasPrefix(link.CredentialID, "session-") || !validCredentialDigest(strings.TrimPrefix(link.CredentialID, "session-")) {
			return nil, ErrNotFound
		}
		err := tx.QueryRowContext(ctx, `SELECT s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.id=? AND u.enabled=1`, link.CredentialDigest, link.ActorID).Scan(&expiry)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	case "service_account":
		if !strings.HasPrefix(link.CredentialID, "token-") {
			return nil, ErrNotFound
		}
		id := strings.TrimPrefix(link.CredentialID, "token-")
		if !signedauth.ValidKeyID(id) {
			return nil, ErrNotFound
		}
		err := tx.QueryRowContext(ctx, `SELECT t.expires_at FROM service_account_tokens t JOIN service_accounts a ON a.id=t.service_account_id WHERE t.id=? AND t.token_hash=? AND a.id=? AND a.enabled=1 AND a.kind='automation' AND t.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM workload_identities w WHERE w.credential_id=t.id)`, id, link.CredentialDigest, link.ActorID).Scan(&expiry)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	default:
		return nil, ErrNotFound
	}
	if expiry.Valid {
		deadline, err := time.Parse(time.RFC3339Nano, expiry.String)
		if err != nil || !deadline.After(now) {
			return nil, ErrNotFound
		}
		return &deadline, nil
	} else if link.ActorType == "user" {
		return nil, ErrNotFound
	}
	return nil, nil
}

// CreateJobAuthorizationLink persists a local-job identity only after the
// current session or static automation credential is checked transactionally.
// The caller must verify the job metadata and permissions with the node.
func (s *Store) CreateJobAuthorizationLink(ctx context.Context, link JobAuthorizationLink, now time.Time) error {
	if !signedauth.ValidKeyID(link.NodeID) || !signedauth.ValidKeyID(link.JobID) || !signedauth.ValidKeyID(link.ActorID) || !signedauth.ValidKeyID(link.CredentialID) || !validCredentialDigest(link.CredentialDigest) || now.IsZero() ||
		link.Binding.ActorID != link.ActorID || link.Binding.CredentialID != link.CredentialID || link.Binding.PlanID != link.JobID || link.Binding.SourceNodeID != link.NodeID || link.Binding.RequestID != "" ||
		link.ConfirmedRevision != 0 || link.ConfirmedDigest != "" || !link.ConfirmedExpiry.IsZero() || link.PendingRevision != 0 || link.PendingEnvelope != "" || !link.PendingExpiry.IsZero() {
		return ErrConflict
	}
	if _, err := signedauth.JobLeaseBinding(link.Binding, 1); err != nil {
		return ErrConflict
	}
	switch link.Binding.Operation {
	case "delete", "copy_local", "move_local":
	default:
		return ErrConflict
	}
	encoded, err := json.Marshal(link.Binding)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := currentLinkedCredentialTx(ctx, tx, link, now); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id=?`, link.NodeID).Scan(&exists); err != nil {
		return err
	}
	if exists != 1 {
		return ErrNotFound
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO job_authorization_links(node_id,job_id,actor_type,actor_id,credential_id,credential_digest,binding,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, link.NodeID, link.JobID, link.ActorType, link.ActorID, link.CredentialID, link.CredentialDigest, string(encoded), stamp, stamp)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','5') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<5 THEN '5' ELSE value END`); err != nil {
		return err
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: link.ActorID, actorType: link.ActorType, action: "bind_job_authorization", resource: "nodes/" + link.NodeID + "/jobs/" + link.JobID, result: "allowed", createdAt: stamp}); err != nil {
		return err
	}
	return tx.Commit()
}

func readJobAuthorizationLink(row scanner) (JobAuthorizationLink, error) {
	var link JobAuthorizationLink
	var binding, created, updated string
	var confirmed, confirmedExpiry, pending, expiry int64
	err := row.Scan(&link.NodeID, &link.JobID, &link.ActorType, &link.ActorID, &link.CredentialID, &link.CredentialDigest, &binding, &confirmed, &link.ConfirmedDigest, &confirmedExpiry, &pending, &link.PendingEnvelope, &expiry, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return JobAuthorizationLink{}, ErrNotFound
	}
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(binding)))
	decoder.DisallowUnknownFields()
	if confirmed < 0 || pending < 0 || filetypes.ValidateUniqueJSON([]byte(binding)) != nil || decoder.Decode(&link.Binding) != nil || decoder.Decode(new(any)) != io.EOF {
		return JobAuthorizationLink{}, ErrConflict
	}
	link.ConfirmedRevision, link.PendingRevision = uint64(confirmed), uint64(pending)
	if !signedauth.ValidKeyID(link.NodeID) || !signedauth.ValidKeyID(link.JobID) || !signedauth.ValidKeyID(link.ActorID) || !signedauth.ValidKeyID(link.CredentialID) || !validCredentialDigest(link.CredentialDigest) ||
		(link.ActorType != "user" && link.ActorType != "service_account") || link.Binding.ActorID != link.ActorID || link.Binding.CredentialID != link.CredentialID || link.Binding.PlanID != link.JobID || link.Binding.SourceNodeID != link.NodeID || link.Binding.RequestID != "" ||
		(confirmed == 0 && (link.ConfirmedDigest != "" || confirmedExpiry != 0)) || (confirmed > 0 && (!validCredentialDigest(link.ConfirmedDigest) || confirmedExpiry <= 0)) ||
		(pending == 0 && (link.PendingEnvelope != "" || expiry != 0)) || (pending > 0 && (pending != confirmed+1 || link.PendingEnvelope == "" || len(link.PendingEnvelope) > 64*1024 || expiry <= 0)) {
		return JobAuthorizationLink{}, ErrConflict
	}
	if _, err := signedauth.JobLeaseBinding(link.Binding, 1); err != nil {
		return JobAuthorizationLink{}, ErrConflict
	}
	switch link.Binding.Operation {
	case "delete", "copy_local", "move_local":
	default:
		return JobAuthorizationLink{}, ErrConflict
	}
	if confirmedExpiry != 0 {
		link.ConfirmedExpiry = time.Unix(0, confirmedExpiry).UTC()
	}
	if expiry != 0 {
		link.PendingExpiry = time.Unix(0, expiry).UTC()
	}
	link.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	link.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	return link, nil
}

const jobLinkSelect = `SELECT node_id,job_id,actor_type,actor_id,credential_id,credential_digest,binding,confirmed_revision,confirmed_digest,confirmed_expiry_ns,pending_revision,pending_envelope,pending_expiry_ns,created_at,updated_at FROM job_authorization_links WHERE node_id=? AND job_id=?`

func (s *Store) GetJobAuthorizationLink(ctx context.Context, nodeID, jobID string) (JobAuthorizationLink, error) {
	return readJobAuthorizationLink(s.db.QueryRowContext(ctx, jobLinkSelect, nodeID, jobID))
}

// StageJobAuthorization records the exact signed envelope before delivery. The
// caller must freshly evaluate policies and grants before staging and retrying.
func (s *Store) StageJobAuthorization(ctx context.Context, nodeID, jobID string, revision uint64, envelope string, keys map[string]ed25519.PublicKey, now time.Time) (JobAuthorizationLink, error) {
	if revision == 0 || revision > math.MaxInt64 || now.IsZero() {
		return JobAuthorizationLink{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	defer tx.Rollback()
	link, err := readJobAuthorizationLink(tx.QueryRowContext(ctx, jobLinkSelect, nodeID, jobID))
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	credentialExpiry, err := currentLinkedCredentialTx(ctx, tx, link, now)
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	if revision != link.ConfirmedRevision+1 {
		return JobAuthorizationLink{}, ErrConflict
	}
	claims, _, err := signedauth.VerifyJobLease(envelope, keys, link.Binding, nodeID, revision, now)
	if err != nil {
		return JobAuthorizationLink{}, ErrConflict
	}
	expiry := time.Unix(claims.ExpiresAt, 0).UTC()
	if credentialExpiry != nil && expiry.After(*credentialExpiry) {
		return JobAuthorizationLink{}, ErrConflict
	}
	if link.PendingRevision != 0 {
		if link.PendingRevision != revision || link.PendingEnvelope != envelope || !link.PendingExpiry.Equal(expiry) {
			return JobAuthorizationLink{}, ErrConflict
		}
		return link, nil
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE job_authorization_links SET pending_revision=?,pending_envelope=?,pending_expiry_ns=?,updated_at=? WHERE node_id=? AND job_id=? AND confirmed_revision=? AND pending_revision=0`, int64(revision), envelope, expiry.UnixNano(), stamp, nodeID, jobID, int64(link.ConfirmedRevision))
	if err != nil {
		return JobAuthorizationLink{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return JobAuthorizationLink{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return JobAuthorizationLink{}, err
	}
	link.PendingRevision, link.PendingEnvelope, link.PendingExpiry, link.UpdatedAt = revision, envelope, expiry, now.UTC()
	return link, nil
}

// ConfirmJobAuthorization advances only the exact envelope confirmed by the
// node. The caller must first authenticate and validate the node response.
func (s *Store) ConfirmJobAuthorization(ctx context.Context, nodeID, jobID string, revision uint64, envelopeDigest string, expiry, now time.Time) error {
	if revision == 0 || revision > math.MaxInt64 || !validCredentialDigest(envelopeDigest) || now.IsZero() {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	link, err := readJobAuthorizationLink(tx.QueryRowContext(ctx, jobLinkSelect, nodeID, jobID))
	if err != nil {
		return err
	}
	credentialExpiry, err := currentLinkedCredentialTx(ctx, tx, link, now)
	if err != nil {
		return err
	}
	if credentialExpiry != nil && expiry.After(*credentialExpiry) {
		return ErrConflict
	}
	if link.PendingRevision == 0 && link.ConfirmedRevision == revision && link.ConfirmedDigest == envelopeDigest && link.ConfirmedExpiry.Equal(expiry) && expiry.After(now) {
		return nil
	}
	if link.PendingRevision != revision || link.PendingEnvelope == "" || security.Digest(link.PendingEnvelope) != envelopeDigest || !link.PendingExpiry.Equal(expiry) || !expiry.After(now) || revision != link.ConfirmedRevision+1 {
		return ErrConflict
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE job_authorization_links SET confirmed_revision=?,confirmed_digest=?,confirmed_expiry_ns=?,pending_revision=0,pending_envelope='',pending_expiry_ns=0,updated_at=? WHERE node_id=? AND job_id=? AND pending_revision=?`, int64(revision), envelopeDigest, expiry.UnixNano(), stamp, nodeID, jobID, int64(revision))
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return ErrConflict
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: link.ActorID, actorType: link.ActorType, action: "confirm_job_authorization", resource: "nodes/" + nodeID + "/jobs/" + jobID, result: "allowed", createdAt: stamp}); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolveExpiredJobAuthorization reconciles an expired pending envelope with
// an authenticated node status. It does not authorize a job or issue a lease.
// Callers must prevent new deliveries of expired envelopes, and re-evaluate
// policies and grants before staging or delivering any subsequent envelope.
func (s *Store) ResolveExpiredJobAuthorization(ctx context.Context, nodeID, jobID string, revision uint64, digest string, expiry, now time.Time) error {
	if now.IsZero() || revision > math.MaxInt64 || (revision == 0 && (digest != "" || !expiry.IsZero())) || (revision > 0 && (!validCredentialDigest(digest) || expiry.IsZero())) {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	link, err := readJobAuthorizationLink(tx.QueryRowContext(ctx, jobLinkSelect, nodeID, jobID))
	if err != nil {
		return err
	}
	if _, err := currentLinkedCredentialTx(ctx, tx, link, now); err != nil {
		return err
	}
	if link.PendingRevision == 0 || link.PendingExpiry.After(now) {
		return ErrConflict
	}
	confirmedRevision, confirmedDigest, confirmedExpiryNS := link.ConfirmedRevision, link.ConfirmedDigest, int64(0)
	if !link.ConfirmedExpiry.IsZero() {
		confirmedExpiryNS = link.ConfirmedExpiry.UnixNano()
	}
	switch {
	case revision == link.PendingRevision && digest == security.Digest(link.PendingEnvelope) && expiry.Equal(link.PendingExpiry):
		confirmedRevision, confirmedDigest, confirmedExpiryNS = revision, digest, expiry.UnixNano()
	case revision == link.ConfirmedRevision && digest == link.ConfirmedDigest && expiry.Equal(link.ConfirmedExpiry):
	default:
		return ErrConflict
	}
	stamp := now.UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE job_authorization_links SET confirmed_revision=?,confirmed_digest=?,confirmed_expiry_ns=?,pending_revision=0,pending_envelope='',pending_expiry_ns=0,updated_at=? WHERE node_id=? AND job_id=? AND confirmed_revision=? AND pending_revision=?`, int64(confirmedRevision), confirmedDigest, confirmedExpiryNS, stamp, nodeID, jobID, int64(link.ConfirmedRevision), int64(link.PendingRevision))
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return ErrConflict
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: link.ActorID, actorType: link.ActorType, action: "resolve_expired_job_authorization", resource: "nodes/" + nodeID + "/jobs/" + jobID, result: "allowed", createdAt: stamp}); err != nil {
		return err
	}
	return tx.Commit()
}

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// WorkloadIdentity is a durable mapping, not a bearer credential. JWTs are
// never stored; credential ID remains stable when the issuer rotates them.
type WorkloadIdentity struct {
	AgentLimits      *AgentLimits `json:"agent_limits,omitempty"`
	CredentialID     string       `json:"credential_id"`
	ServiceAccountID string       `json:"service_account_id"`
	ProviderID       string       `json:"provider_id"`
	Issuer           string       `json:"issuer"`
	Subject          string       `json:"subject"`
	Audience         string       `json:"audience"`
	Enabled          bool         `json:"enabled"`
	Revoked          bool         `json:"revoked"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

// CreateWorkloadIdentity creates both the mapping and its quota-bearing
// credential atomically. The synthetic token hash contains a colon and can
// never equal the base64url digest of any static bearer token.
// This operation is internal until provider configuration and authentication
// are connected and revalidation is enforced at all credential call sites.
func (s *Store) CreateWorkloadIdentity(ctx context.Context, identity WorkloadIdentity, limits *AgentLimits, actorID, actorType, correlationID string) error {
	if !validWorkloadField(identity.CredentialID, false, 128) || strings.ContainsAny(identity.CredentialID, "/\\:") ||
		!validWorkloadField(identity.ServiceAccountID, false, 128) || !validWorkloadField(identity.ProviderID, false, 128) ||
		!validWorkloadField(identity.Issuer, true, 2048) || !validWorkloadField(identity.Subject, false, 2048) || !validWorkloadField(identity.Audience, false, 2048) {
		return ErrConflict
	}
	encodedLimits, err := json.Marshal(limits)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM service_accounts WHERE id=?`, identity.ServiceAccountID).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if enabled == 0 {
		return ErrConflict
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `INSERT INTO service_account_tokens(id,service_account_id,name,token_hash,created_at,agent_limits) VALUES(?,?,?,?,?,?)`,
		identity.CredentialID, identity.ServiceAccountID, "workload identity", "workload:"+identity.CredentialID, now, string(encodedLimits))
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO workload_identities(credential_id,provider_id,issuer,subject,audience,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)`,
		identity.CredentialID, identity.ProviderID, identity.Issuer, identity.Subject, identity.Audience, now, now)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO metadata(key,value) VALUES('minimum_security_version','4') ON CONFLICT(key) DO UPDATE SET value=CASE WHEN CAST(value AS INTEGER)<4 THEN '4' ELSE value END`); err != nil {
		return err
	}
	if err = appendAuditTx(ctx, tx, auditRecord{actorID: actorID, actorType: actorType, action: "create_workload_identity", resource: "workload-identities/" + identity.CredentialID, result: "allowed", correlationID: correlationID, createdAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

// ActiveWorkloadIdentity resolves only an explicit mapping for an enabled
// account and a non-revoked credential. Callers must verify the JWT first.
func (s *Store) ActiveWorkloadIdentity(ctx context.Context, provider, issuer, subject, audience string) (WorkloadIdentity, error) {
	var identity WorkloadIdentity
	var created, updated string
	var enabled int
	var expiry sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT w.credential_id,t.service_account_id,w.provider_id,w.issuer,w.subject,w.audience,w.enabled,w.created_at,w.updated_at,t.expires_at
FROM workload_identities w JOIN service_account_tokens t ON t.id=w.credential_id JOIN service_accounts a ON a.id=t.service_account_id
WHERE w.provider_id=? AND w.issuer=? AND w.subject=? AND w.audience=? AND w.enabled=1 AND a.enabled=1 AND t.revoked_at IS NULL`,
		provider, issuer, subject, audience).Scan(&identity.CredentialID, &identity.ServiceAccountID, &identity.ProviderID, &identity.Issuer, &identity.Subject, &identity.Audience, &enabled, &created, &updated, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return WorkloadIdentity{}, ErrNotFound
	}
	if err != nil {
		return WorkloadIdentity{}, err
	}
	if expiry.Valid {
		deadline, err := time.Parse(time.RFC3339Nano, expiry.String)
		if err != nil || !deadline.After(time.Now().UTC()) {
			return WorkloadIdentity{}, ErrNotFound
		}
	}
	identity.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return WorkloadIdentity{}, err
	}
	identity.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return WorkloadIdentity{}, err
	}
	identity.Enabled = enabled != 0
	return identity, nil
}

// SetWorkloadIdentityEnabled preserves the credential and its quota history.
// The future HTTP integration must also cancel active requests when disabling.
func (s *Store) SetWorkloadIdentityEnabled(ctx context.Context, accountID, id string, enabled bool, actorID, actorType, correlationID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `UPDATE workload_identities SET enabled=?,updated_at=? WHERE credential_id=? AND EXISTS(SELECT 1 FROM service_account_tokens WHERE id=credential_id AND service_account_id=?)`, boolInt(enabled), now, id, accountID)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return ErrNotFound
	}
	action := "disable_workload_identity"
	if enabled {
		action = "enable_workload_identity"
	}
	if err := appendAuditTx(ctx, tx, auditRecord{actorID: actorID, actorType: actorType, action: action, resource: "workload-identities/" + id, result: "allowed", correlationID: correlationID, createdAt: now}); err != nil {
		return err
	}
	return tx.Commit()
}

func scanWorkloadIdentity(scanner interface{ Scan(...any) error }) (WorkloadIdentity, error) {
	var identity WorkloadIdentity
	var created, updated, limits string
	var enabled int
	var revoked sql.NullString
	err := scanner.Scan(&identity.CredentialID, &identity.ServiceAccountID, &identity.ProviderID, &identity.Issuer, &identity.Subject, &identity.Audience, &enabled, &created, &updated, &revoked, &limits)
	if err != nil {
		return WorkloadIdentity{}, err
	}
	identity.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return WorkloadIdentity{}, err
	}
	identity.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return WorkloadIdentity{}, err
	}
	if err := json.Unmarshal([]byte(limits), &identity.AgentLimits); err != nil {
		return WorkloadIdentity{}, err
	}
	identity.Enabled, identity.Revoked = enabled != 0, revoked.Valid
	return identity, nil
}

const workloadIdentitySelect = `SELECT w.credential_id,t.service_account_id,w.provider_id,w.issuer,w.subject,w.audience,w.enabled,w.created_at,w.updated_at,t.revoked_at,t.agent_limits
FROM workload_identities w JOIN service_account_tokens t ON t.id=w.credential_id `

func (s *Store) GetWorkloadIdentity(ctx context.Context, accountID, id string) (WorkloadIdentity, error) {
	identity, err := scanWorkloadIdentity(s.db.QueryRowContext(ctx, workloadIdentitySelect+`WHERE t.service_account_id=? AND w.credential_id=?`, accountID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return WorkloadIdentity{}, ErrNotFound
	}
	return identity, err
}

func (s *Store) ListWorkloadIdentities(ctx context.Context, accountID string) ([]WorkloadIdentity, error) {
	if _, err := s.GetServiceAccount(ctx, accountID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, workloadIdentitySelect+`WHERE t.service_account_id=? ORDER BY w.created_at,w.credential_id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	identities := []WorkloadIdentity{}
	for rows.Next() {
		identity, err := scanWorkloadIdentity(rows)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func validWorkloadField(value string, empty bool, max int) bool {
	if value == "" {
		return empty
	}
	if len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

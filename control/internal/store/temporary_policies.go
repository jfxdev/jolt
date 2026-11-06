package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type TemporaryPolicyAssignment struct {
	PolicyID  string    `json:"policy_id"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Temporary assignments are stored separately so an older replace-all client
// cannot silently turn a time-limited grant into a permanent assignment.
func (s *Store) GrantTemporaryPolicy(ctx context.Context, subjectType, subjectID, policyID, actorID, actorType, correlationID string, duration time.Duration) (TemporaryPolicyAssignment, error) {
	if duration <= 0 || duration > time.Hour {
		return TemporaryPolicyAssignment{}, errors.New("invalid temporary assignment duration")
	}
	var subjectQuery string
	switch subjectType {
	case "user":
		subjectQuery = `SELECT COUNT(*) FROM users WHERE id=?`
	case "service_account":
		subjectQuery = `SELECT COUNT(*) FROM service_accounts WHERE id=?`
	default:
		return TemporaryPolicyAssignment{}, ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TemporaryPolicyAssignment{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, subjectQuery, subjectID).Scan(&count); err != nil {
		return TemporaryPolicyAssignment{}, err
	}
	if count == 0 {
		return TemporaryPolicyAssignment{}, ErrNotFound
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policies WHERE id=?`, policyID).Scan(&count); err != nil {
		return TemporaryPolicyAssignment{}, err
	}
	if count == 0 {
		return TemporaryPolicyAssignment{}, ErrNotFound
	}
	now := time.Now().UTC()
	assignment := TemporaryPolicyAssignment{PolicyID: policyID, CreatedBy: actorID, CreatedAt: now, ExpiresAt: now.Add(duration)}
	_, err = tx.ExecContext(ctx, `INSERT INTO temporary_policy_assignments(policy_id,subject_type,subject_id,created_at,created_by,expires_at_ns) VALUES(?,?,?,?,?,?)
ON CONFLICT(policy_id,subject_type,subject_id) DO UPDATE SET created_at=excluded.created_at,created_by=excluded.created_by,expires_at_ns=excluded.expires_at_ns`,
		policyID, subjectType, subjectID, now.Format(time.RFC3339Nano), actorID, assignment.ExpiresAt.UnixNano())
	if err != nil {
		return TemporaryPolicyAssignment{}, err
	}
	detail, _ := json.Marshal(map[string]any{"policy_id": policyID, "subject_type": subjectType, "subject_id": subjectID, "expires_at": assignment.ExpiresAt})
	err = appendAuditTx(ctx, tx, auditRecord{actorID: actorID, actorType: actorType, action: "grant_temporary_policy", resource: "policy_assignments/" + subjectType + "/" + subjectID, result: "allowed", correlationID: correlationID, createdAt: now.Format(time.RFC3339Nano), detail: string(detail)})
	if err != nil {
		return TemporaryPolicyAssignment{}, err
	}
	if err := tx.Commit(); err != nil {
		return TemporaryPolicyAssignment{}, err
	}
	return assignment, nil
}

func (s *Store) TemporaryPolicies(ctx context.Context, subjectType, subjectID string) ([]TemporaryPolicyAssignment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT policy_id,created_by,created_at,expires_at_ns FROM temporary_policy_assignments
WHERE subject_type=? AND subject_id=? AND expires_at_ns>? ORDER BY policy_id`, subjectType, subjectID, time.Now().UTC().UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TemporaryPolicyAssignment, 0)
	for rows.Next() {
		var item TemporaryPolicyAssignment
		var created string
		var expires int64
		if err := rows.Scan(&item.PolicyID, &item.CreatedBy, &created, &expires); err != nil {
			return nil, err
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		item.ExpiresAt = time.Unix(0, expires).UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeTemporaryPolicy(ctx context.Context, subjectType, subjectID, policyID, actorID, actorType, correlationID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM temporary_policy_assignments WHERE policy_id=? AND subject_type=? AND subject_id=?`, policyID, subjectType, subjectID)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count == 0 {
		return ErrNotFound
	}
	detail, _ := json.Marshal(map[string]any{"policy_id": policyID, "subject_type": subjectType, "subject_id": subjectID})
	err = appendAuditTx(ctx, tx, auditRecord{actorID: actorID, actorType: actorType, action: "revoke_temporary_policy", resource: "policy_assignments/" + subjectType + "/" + subjectID, result: "allowed", correlationID: correlationID, detail: string(detail)})
	if err != nil {
		return err
	}
	return tx.Commit()
}
